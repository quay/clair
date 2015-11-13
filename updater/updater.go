// Copyright 2015 quay-sec authors
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
	"math/rand"
	"strconv"
	"time"

	"github.com/coreos/pkg/capnslog"
	"github.com/coreos/quay-sec/database"
	"github.com/coreos/quay-sec/health"
	"github.com/coreos/quay-sec/utils"
	"github.com/pborman/uuid"
)

const (
	flagName            = "updater"
	refreshLockDuration = time.Minute * 8
	lockDuration        = refreshLockDuration + time.Minute*2

	// healthMaxConsecutiveLocalFailures defines the number of times the updater
	// can fail before we should tag it as unhealthy
	healthMaxConsecutiveLocalFailures = 5
)

var (
	log = capnslog.NewPackageLogger("github.com/coreos/quay-sec", "updater")

	healthLatestSuccessfulUpdate   time.Time
	healthLockOwner                string
	healthIdentifier               string
	healthConsecutiveLocalFailures int
	healthNotes                    []string
)

func init() {
	health.RegisterHealthchecker("updater", Healthcheck)
}

// Run updates the vulnerability database at regular intervals
func Run(interval time.Duration, st *utils.Stopper) {
	defer st.End()

	// Do not run the updater if the interval is 0
	if interval == 0 {
		log.Infof("updater service is disabled.")
		return
	}

	whoAmI := uuid.New()
	healthIdentifier = whoAmI
	log.Infof("updater service started. lock identifier: %s", whoAmI)

	for {
		// Set the next update time to (last update time + interval) or now if there
		// is no last update time stored in database (first update) or if an error
		// occurs
		nextUpdate := time.Now().UTC()
		if lastUpdateTSS, err := database.GetFlagValue(flagName); err == nil && lastUpdateTSS != "" {
			if lastUpdateTS, err := strconv.ParseInt(lastUpdateTSS, 10, 64); err == nil {
				healthLatestSuccessfulUpdate = time.Unix(lastUpdateTS, 0)
				nextUpdate = time.Unix(lastUpdateTS, 0).Add(interval)
			}
		}

		// If the next update timer is in the past, then try to update.
		if nextUpdate.Before(time.Now().UTC()) {
			// Attempt to get a lock on the the update.
			log.Debug("attempting to obtain update lock")
			hasLock, hasLockUntil := database.Lock(flagName, lockDuration, whoAmI)
			if hasLock {
				healthLockOwner = healthIdentifier

				// Launch update in a new go routine.
				doneC := make(chan bool, 1)
				go func() {
					Update()
					doneC <- true
				}()

				// Refresh the lock until the update is done.
				for done := false; !done; {
					select {
					case <-doneC:
						done = true
					case <-time.After(refreshLockDuration):
						database.Lock(flagName, lockDuration, whoAmI)
					}
				}

				// Write the last update time to the database and set the next update
				// time.
				now := time.Now().UTC()
				database.UpdateFlag(flagName, strconv.FormatInt(now.Unix(), 10))
				healthLatestSuccessfulUpdate = now
				nextUpdate = now.Add(interval)

				// Unlock the update.
				database.Unlock(flagName, whoAmI)
			} else {
				lockOwner, lockExpiration, err := database.LockInfo(flagName)
				if err != nil {
					log.Debug("update lock is already taken")
					nextUpdate = hasLockUntil
				} else {
					log.Debugf("update lock is already taken by %s until %v", lockOwner, lockExpiration)
					nextUpdate = lockExpiration
					healthLockOwner = lockOwner
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

	// Fetch updates in parallel.
	var status = true
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
	var responses []*FetcherResponse
	var notes []string
	for i := 0; i < len(fetchers); {
		select {
		case resp := <-responseC:
			if resp != nil {
				responses = append(responses, resp)
				notes = append(notes, resp.Notes...)
			}
			i++
		}
	}

	close(responseC)

	// TODO(Quentin-M): Merge responses together
	// TODO(Quentin-M): Complete informations using NVD

	// Store flags out of the response struct.
	flags := make(map[string]string)
	for _, response := range responses {
		if response.FlagName != "" && response.FlagValue != "" {
			flags[response.FlagName] = response.FlagValue
		}
	}

	// Update health notes.
	healthNotes = notes

	// Build list of packages.
	var packages []*database.Package
	for _, response := range responses {
		for _, v := range response.Vulnerabilities {
			packages = append(packages, v.FixedIn...)
		}
	}

	// Insert packages into the database.
	log.Tracef("beginning insertion of %d packages for update", len(packages))
	t := time.Now()
	err := database.InsertPackages(packages)
	log.Tracef("inserting %d packages took %v", len(packages), time.Since(t))
	if err != nil {
		log.Errorf("an error occured when inserting packages for update: %s", err)
		updateHealth(false)
		return
	}
	packages = nil

	// Build a list of vulnerabilties.
	var vulnerabilities []*database.Vulnerability
	for _, response := range responses {
		for _, v := range response.Vulnerabilities {
			var packageNodes []string
			for _, pkg := range v.FixedIn {
				packageNodes = append(packageNodes, pkg.Node)
			}
			vulnerabilities = append(vulnerabilities, &database.Vulnerability{ID: v.ID, Link: v.Link, Priority: v.Priority, Description: v.Description, FixedInNodes: packageNodes})
		}
	}
	responses = nil

	// Insert vulnerabilities into the database.
	log.Tracef("beginning insertion of %d vulnerabilities for update", len(vulnerabilities))
	t = time.Now()
	notifications, err := database.InsertVulnerabilities(vulnerabilities)
	log.Tracef("inserting %d vulnerabilities took %v", len(vulnerabilities), time.Since(t))
	if err != nil {
		log.Errorf("an error occured when inserting vulnerabilities for update: %s", err)
		updateHealth(false)
		return
	}
	vulnerabilities = nil

	// Insert notifications into the database.
	err = database.InsertNotifications(notifications, database.GetDefaultNotificationWrapper())
	if err != nil {
		log.Errorf("an error occured when inserting notifications for update: %s", err)
		updateHealth(false)
		return
	}
	notifications = nil

	// Update flags in the database.
	for flagName, flagValue := range flags {
		database.UpdateFlag(flagName, flagValue)
	}

	// Update health depending on the status of the fetchers.
	updateHealth(status)

	log.Info("update finished")
}

func updateHealth(s bool) {
	if s == false {
		healthConsecutiveLocalFailures++
	} else {
		healthConsecutiveLocalFailures = 0
	}
}

// Healthcheck returns the health of the updater service.
func Healthcheck() health.Status {
	return health.Status{
		IsEssential: false,
		IsHealthy:   healthConsecutiveLocalFailures < healthMaxConsecutiveLocalFailures,
		Details: struct {
			HealthIdentifier         string
			HealthLockOwner          string
			LatestSuccessfulUpdate   time.Time
			ConsecutiveLocalFailures int
			Notes                    []string `json:",omitempty"`
		}{
			HealthIdentifier:         healthIdentifier,
			HealthLockOwner:          healthLockOwner,
			LatestSuccessfulUpdate:   healthLatestSuccessfulUpdate,
			ConsecutiveLocalFailures: healthConsecutiveLocalFailures,
			Notes: healthNotes,
		},
	}
}
