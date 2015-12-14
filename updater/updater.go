// Copyright 2015 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package updater updates the vulnerability database periodically using
// the registered vulnerability fetchers.
package updater

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"github.com/coreos/clair/config"
	"github.com/coreos/clair/database"
	"github.com/coreos/clair/health"
	"github.com/coreos/clair/utils"
	"github.com/coreos/pkg/capnslog"
	"github.com/pborman/uuid"
)

const (
	flagName            = "updater"
	notesFlagName       = "updater/notes"
	refreshLockDuration = time.Minute * 8
	lockDuration        = refreshLockDuration + time.Minute*2
)

var log = capnslog.NewPackageLogger("github.com/coreos/clair", "updater")

// Run updates the vulnerability database at regular intervals.
func Run(config *config.UpdaterConfig, st *utils.Stopper) {
	defer st.End()

	// Do not run the updater if there is no config or if the interval is 0.
	if config == nil || config.Interval == 0 {
		log.Infof("updater service is disabled.")
		return
	}

	// Register healthchecker.
	health.RegisterHealthchecker("updater", Healthcheck)

	whoAmI := uuid.New()
	log.Infof("updater service started. lock identifier: %s", whoAmI)

	for {
		// Set the next update time to (last update time + interval) or now if there
		// is no last update time stored in database (first update) or if an error
		// occurs.
		var nextUpdate time.Time
		var stop bool
		if lastUpdate := getLastUpdate(); !lastUpdate.IsZero() {
			nextUpdate = lastUpdate.Add(config.Interval)
		} else {
			nextUpdate = time.Now().UTC()
		}

		// If the next update timer is in the past, then try to update.
		if nextUpdate.Before(time.Now().UTC()) {
			// Attempt to get a lock on the the update.
			log.Debug("attempting to obtain update lock")
			hasLock, hasLockUntil := database.Lock(flagName, lockDuration, whoAmI)
			if hasLock {
				// Launch update in a new go routine.
				doneC := make(chan bool, 1)
				go func() {
					Update()
					doneC <- true
				}()

				for done := false; !done && !stop; {
					select {
					case <-doneC:
						done = true
					case <-time.After(refreshLockDuration):
						// Refresh the lock until the update is done.
						database.Lock(flagName, lockDuration, whoAmI)
					case <-st.Chan():
						stop = true
					}
				}

				// Unlock the update.
				database.Unlock(flagName, whoAmI)

				if stop {
					break
				}
				continue
			} else {
				lockOwner, lockExpiration, err := database.LockInfo(flagName)
				if err != nil {
					log.Debug("update lock is already taken")
					nextUpdate = hasLockUntil
				} else {
					log.Debugf("update lock is already taken by %s until %v", lockOwner, lockExpiration)
					nextUpdate = lockExpiration
				}
			}
		}

		// Sleep, but remain stoppable until approximately the next update time.
		now := time.Now().UTC()
		waitUntil := nextUpdate.Add(time.Duration(rand.ExpFloat64()/0.5) * time.Second)
		log.Debugf("next update attempt scheduled for %v.", waitUntil)
		if !waitUntil.Before(now) {
			if !st.Sleep(waitUntil.Sub(time.Now())) {
				break
			}
		}
	}

	log.Info("updater service stopped")
}

// Update fetches all the vulnerabilities from the registered fetchers, upserts
// them into the database and then sends notifications.
func Update() {
	log.Info("updating vulnerabilities")

	// Fetch updates.
	status, responses := fetch()

	// Merge responses.
	vulnerabilities, packages, flags, notes, err := mergeAndVerify(responses)
	if err != nil {
		log.Errorf("an error occured when merging update responses: %s", err)
		return
	}
	responses = nil

	// TODO(Quentin-M): Complete informations using NVD

	// Insert packages.
	log.Tracef("beginning insertion of %d packages for update", len(packages))
	err = database.InsertPackages(packages)
	if err != nil {
		log.Errorf("an error occured when inserting packages for update: %s", err)
		return
	}
	packages = nil

	// Insert vulnerabilities.
	log.Tracef("beginning insertion of %d vulnerabilities for update", len(vulnerabilities))
	notifications, err := database.InsertVulnerabilities(vulnerabilities)
	if err != nil {
		log.Errorf("an error occured when inserting vulnerabilities for update: %s", err)
		return
	}
	vulnerabilities = nil

	// Insert notifications into the database.
	err = database.InsertNotifications(notifications, database.GetDefaultNotificationWrapper())
	if err != nil {
		log.Errorf("an error occured when inserting notifications for update: %s", err)
		return
	}
	notifications = nil

	// Update flags and notes.
	for flagName, flagValue := range flags {
		database.UpdateFlag(flagName, flagValue)
	}
	database.UpdateFlag(notesFlagName, notes)

	// Update last successful update if every fetchers worked properly.
	if status {
		database.UpdateFlag(flagName, strconv.FormatInt(time.Now().UTC().Unix(), 10))
	}
	log.Info("update finished")
}

// fetch get data from the registered fetchers, in parallel.
func fetch() (status bool, responses []*FetcherResponse) {
	// Fetch updates in parallel.
	status = true
	var responseC = make(chan *FetcherResponse, 0)
	for n, f := range fetchers {
		go func(name string, fetcher Fetcher) {
			response, err := fetcher.FetchUpdate()
			if err != nil {
				log.Errorf("an error occured when fetching update '%s': %s.", name, err)
				status = false
				responseC <- nil
				return
			}

			responseC <- &response
		}(n, f)
	}

	// Collect results of updates.
	for i := 0; i < len(fetchers); i++ {
		resp := <-responseC
		if resp != nil {
			responses = append(responses, resp)
		}
	}

	close(responseC)
	return
}

// merge put all the responses together (vulnerabilities, packages, flags, notes), ensure the
// uniqueness of vulnerabilities and packages and verify that every vulnerability's fixedInNodes
// have their corresponding package definition.
func mergeAndVerify(responses []*FetcherResponse) (svulnerabilities []*database.Vulnerability, spackages []*database.Package, flags map[string]string, snotes string, err error) {
	vulnerabilities := make(map[string]*database.Vulnerability)
	packages := make(map[string]*database.Package)
	flags = make(map[string]string)
	var notes []string

	// Merge responses.
	for _, response := range responses {
		// Notes
		notes = append(notes, response.Notes...)
		// Flags
		if response.FlagName != "" && response.FlagValue != "" {
			flags[response.FlagName] = response.FlagValue
		}
		// Packages
		for _, p := range response.Packages {
			node := p.GetNode()
			if _, ok := packages[node]; !ok {
				packages[node] = p
			}
		}
		// Vulnerabilities
		for _, v := range response.Vulnerabilities {
			if vulnerability, ok := vulnerabilities[v.ID]; !ok {
				vulnerabilities[v.ID] = v
			} else {
				mergeVulnerability(vulnerability, v)
			}
		}
	}

	// Verify that the packages used in the vulnerabilities are specified.
	for _, v := range vulnerabilities {
		for _, node := range v.FixedInNodes {
			if _, ok := packages[node]; !ok {
				err = fmt.Errorf("vulnerability %s is fixed by an unspecified package", v.ID)
				return
			}
		}
	}

	// Convert data and return
	for _, v := range vulnerabilities {
		svulnerabilities = append(svulnerabilities, v)
	}
	for _, p := range packages {
		spackages = append(spackages, p)
	}

	bnotes, _ := json.Marshal(notes)
	snotes = string(bnotes)

	return
}

// mergeVulnerability updates the target vulnerability structure using the specified one.
func mergeVulnerability(target, source *database.Vulnerability) {
	if source.Link != "" {
		target.Link = source.Link
	}
	if source.Description != "" {
		target.Description = source.Description
	}
	if source.Priority.Compare(target.Priority) > 0 {
		target.Priority = source.Priority
	}
	for _, node := range source.FixedInNodes {
		if !utils.Contains(node, target.FixedInNodes) {
			target.FixedInNodes = append(target.FixedInNodes, node)
		}
	}
}

// Healthcheck returns the health of the updater service.
func Healthcheck() health.Status {
	notes := getNotes()

	return health.Status{
		IsEssential: false,
		IsHealthy:   len(notes) == 0,
		Details: struct {
			LatestSuccessfulUpdate time.Time
			Notes                  []string `json:",omitempty"`
		}{
			LatestSuccessfulUpdate: getLastUpdate(),
			Notes: notes,
		},
	}
}

func getLastUpdate() time.Time {
	if lastUpdateTSS, err := database.GetFlagValue(flagName); err == nil && lastUpdateTSS != "" {
		if lastUpdateTS, err := strconv.ParseInt(lastUpdateTSS, 10, 64); err == nil {
			return time.Unix(lastUpdateTS, 0).UTC()
		}
	}
	return time.Time{}
}

func getNotes() (notes []string) {
	if jsonNotes, err := database.GetFlagValue(notesFlagName); err == nil && jsonNotes != "" {
		json.Unmarshal([]byte(jsonNotes), notes)
	}
	return
}
