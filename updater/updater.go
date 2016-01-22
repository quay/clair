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
	"math/rand"
	"strconv"
	"time"

	"github.com/coreos/clair/config"
	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils"
	"github.com/coreos/pkg/capnslog"
	"github.com/pborman/uuid"
)

const (
	flagName      = "updater/last"
	notesFlagName = "updater/notes"

	lockName            = "updater"
	lockDuration        = refreshLockDuration + time.Minute*2
	refreshLockDuration = time.Minute * 8
)

var log = capnslog.NewPackageLogger("github.com/coreos/clair", "updater")

// Run updates the vulnerability database at regular intervals.
func Run(config *config.UpdaterConfig, datastore database.Datastore, st *utils.Stopper) {
	defer st.End()

	// Do not run the updater if there is no config or if the interval is 0.
	if config == nil || config.Interval == 0 {
		log.Infof("updater service is disabled.")
		return
	}

	whoAmI := uuid.New()
	log.Infof("updater service started. lock identifier: %s", whoAmI)

	for {
		// Set the next update time to (last update time + interval) or now if there
		// is no last update time stored in database (first update) or if an error
		// occurs.
		var nextUpdate time.Time
		var stop bool
		if lastUpdate := getLastUpdate(datastore); !lastUpdate.IsZero() {
			nextUpdate = lastUpdate.Add(config.Interval)
		} else {
			nextUpdate = time.Now().UTC()
		}

		// If the next update timer is in the past, then try to update.
		if nextUpdate.Before(time.Now().UTC()) {
			// Attempt to get a lock on the the update.
			log.Debug("attempting to obtain update lock")
			hasLock, hasLockUntil := datastore.Lock(lockName, whoAmI, lockDuration, false)
			if hasLock {
				// Launch update in a new go routine.
				doneC := make(chan bool, 1)
				go func() {
					Update(datastore)
					doneC <- true
				}()

				for done := false; !done && !stop; {
					select {
					case <-doneC:
						done = true
					case <-time.After(refreshLockDuration):
						// Refresh the lock until the update is done.
						datastore.Lock(lockName, whoAmI, lockDuration, true)
					case <-st.Chan():
						stop = true
					}
				}

				// Unlock the update.
				datastore.Unlock(lockName, whoAmI)

				if stop {
					break
				}
				continue
			} else {
				lockOwner, lockExpiration, err := datastore.FindLock(lockName)
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
func Update(datastore database.Datastore) {
	log.Info("updating vulnerabilities")

	// Fetch updates.
	status, vulnerabilities, flags, notes := fetch(datastore)

	// TODO(Quentin-M): Complete informations using NVD

	// Insert vulnerabilities.
	log.Tracef("beginning insertion of %d vulnerabilities for update", len(vulnerabilities))
	err := datastore.InsertVulnerabilities(vulnerabilities)
	if err != nil {
		log.Errorf("an error occured when inserting vulnerabilities for update: %s", err)
		return
	}
	vulnerabilities = nil

	// Update flags and notes.
	for flagName, flagValue := range flags {
		datastore.InsertKeyValue(flagName, flagValue)
	}

	bnotes, _ := json.Marshal(notes)
	datastore.InsertKeyValue(notesFlagName, string(bnotes))

	// Update last successful update if every fetchers worked properly.
	if status {
		datastore.InsertKeyValue(flagName, strconv.FormatInt(time.Now().UTC().Unix(), 10))
	}
	log.Info("update finished")
}

// fetch get data from the registered fetchers, in parallel.
func fetch(datastore database.Datastore) (bool, []database.Vulnerability, map[string]string, []string) {
	var vulnerabilities []database.Vulnerability
	var notes []string
	status := true
	flags := make(map[string]string)

	// Fetch updates in parallel.
	var responseC = make(chan *FetcherResponse, 0)
	for n, f := range fetchers {
		go func(name string, fetcher Fetcher) {
			response, err := fetcher.FetchUpdate(datastore)
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
			vulnerabilities = append(vulnerabilities, resp.Vulnerabilities...)
			notes = append(notes, resp.Notes...)
			if resp.FlagName != "" && resp.FlagValue != "" {
				flags[resp.FlagName] = resp.FlagValue
			}
		}
	}

	close(responseC)
	return status, vulnerabilities, flags, notes
}

func getLastUpdate(datastore database.Datastore) time.Time {
	if lastUpdateTSS, err := datastore.GetKeyValue(flagName); err == nil && lastUpdateTSS != "" {
		if lastUpdateTS, err := strconv.ParseInt(lastUpdateTSS, 10, 64); err == nil {
			return time.Unix(lastUpdateTS, 0).UTC()
		}
	}
	return time.Time{}
}

func getNotes(datastore database.Datastore) (notes []string) {
	if jsonNotes, err := datastore.GetKeyValue(notesFlagName); err == nil && jsonNotes != "" {
		json.Unmarshal([]byte(jsonNotes), notes)
	}
	return
}
