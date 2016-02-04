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
	"math/rand"
	"strconv"
	"sync"
	"time"

	"github.com/coreos/clair/config"
	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils"
	"github.com/coreos/pkg/capnslog"
	"github.com/pborman/uuid"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	flagName      = "updater/last"
	notesFlagName = "updater/notes"

	lockName            = "updater"
	lockDuration        = refreshLockDuration + time.Minute*2
	refreshLockDuration = time.Minute * 8
)

var (
	log = capnslog.NewPackageLogger("github.com/coreos/clair", "updater")

	promUpdaterErrorsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "clair_updater_errors_total",
		Help: "Numbers of errors that the updater generated.",
	})

	promUpdaterDurationSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "clair_updater_duration_seconds",
		Help: "Time it takes to update the vulnerability database.",
	})

	promUpdaterNotesTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "clair_updater_notes_total",
		Help: "Number of notes that the vulnerability fetchers generated.",
	})
)

func init() {
	prometheus.MustRegister(promUpdaterErrorsTotal)
	prometheus.MustRegister(promUpdaterDurationSeconds)
	prometheus.MustRegister(promUpdaterNotesTotal)
}

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
		var stop bool

		// Determine if this is the first update and define the next update time.
		// The next update time is (last update time + interval) or now if this is the first update.
		nextUpdate := time.Now().UTC()
		lastUpdate, firstUpdate, err := getLastUpdate(datastore)
		if err != nil {
			log.Errorf("an error occured while getting the last update time")
			nextUpdate = nextUpdate.Add(config.Interval)
		} else if firstUpdate == false {
			nextUpdate = lastUpdate.Add(config.Interval)
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
					Update(datastore, firstUpdate)
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

	// Clean resources.
	for _, metadataFetcher := range metadataFetchers {
		metadataFetcher.Clean()
	}
	for _, fetcher := range fetchers {
		fetcher.Clean()
	}

	log.Info("updater service stopped")
}

// Update fetches all the vulnerabilities from the registered fetchers, upserts
// them into the database and then sends notifications.
func Update(datastore database.Datastore, firstUpdate bool) {
	defer setUpdaterDuration(time.Now())

	log.Info("updating vulnerabilities")

	// Fetch updates.
	status, vulnerabilities, flags, notes := fetch(datastore)

	// Insert vulnerabilities.
	log.Tracef("inserting %d vulnerabilities for update", len(vulnerabilities))
	err := datastore.InsertVulnerabilities(vulnerabilities, !firstUpdate)
	if err != nil {
		promUpdaterErrorsTotal.Inc()
		log.Errorf("an error occured when inserting vulnerabilities for update: %s", err)
		return
	}
	vulnerabilities = nil

	// Update flags.
	for flagName, flagValue := range flags {
		datastore.InsertKeyValue(flagName, flagValue)
	}

	// Log notes.
	for _, note := range notes {
		log.Warningf("fetcher note: %s", note)
	}
	promUpdaterNotesTotal.Set(float64(len(notes)))

	// Update last successful update if every fetchers worked properly.
	if status {
		datastore.InsertKeyValue(flagName, strconv.FormatInt(time.Now().UTC().Unix(), 10))
	}

	log.Info("update finished")
}

func setUpdaterDuration(start time.Time) {
	promUpdaterDurationSeconds.Set(time.Since(start).Seconds())
}

// fetch get data from the registered fetchers, in parallel.
func fetch(datastore database.Datastore) (bool, []database.Vulnerability, map[string]string, []string) {
	var vulnerabilities []database.Vulnerability
	var notes []string
	status := true
	flags := make(map[string]string)

	// Fetch updates in parallel.
	log.Info("fetching vulnerability updates")
	var responseC = make(chan *FetcherResponse, 0)
	for n, f := range fetchers {
		go func(name string, fetcher Fetcher) {
			response, err := fetcher.FetchUpdate(datastore)
			if err != nil {
				promUpdaterErrorsTotal.Inc()
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
			vulnerabilities = append(vulnerabilities, doVulnerabilitiesNamespacing(resp.Vulnerabilities)...)
			notes = append(notes, resp.Notes...)
			if resp.FlagName != "" && resp.FlagValue != "" {
				flags[resp.FlagName] = resp.FlagValue
			}
		}
	}

	close(responseC)
	return status, addMetadata(datastore, vulnerabilities), flags, notes
}

// Add metadata to the specified vulnerabilities using the registered MetadataFetchers, in parallel.
func addMetadata(datastore database.Datastore, vulnerabilities []database.Vulnerability) []database.Vulnerability {
	if len(metadataFetchers) == 0 {
		return vulnerabilities
	}

	log.Info("adding metadata to vulnerabilities")

	// Wrap vulnerabilities in VulnerabilityWithLock.
	// It ensures that only one metadata fetcher at a time can modify the Metadata map.
	vulnerabilitiesWithLocks := make([]*VulnerabilityWithLock, 0, len(vulnerabilities))
	for i := 0; i < len(vulnerabilities); i++ {
		vulnerabilitiesWithLocks = append(vulnerabilitiesWithLocks, &VulnerabilityWithLock{
			Vulnerability: &vulnerabilities[i],
		})
	}

	var wg sync.WaitGroup
	wg.Add(len(metadataFetchers))

	for n, f := range metadataFetchers {
		go func(name string, metadataFetcher MetadataFetcher) {
			defer wg.Done()

			// Load the metadata fetcher.
			if err := metadataFetcher.Load(datastore); err != nil {
				promUpdaterErrorsTotal.Inc()
				log.Errorf("an error occured when loading metadata fetcher '%s': %s.", name, err)
				return
			}

			// Add metadata to each vulnerability.
			for _, vulnerability := range vulnerabilitiesWithLocks {
				metadataFetcher.AddMetadata(vulnerability)
			}

			metadataFetcher.Unload()
		}(n, f)
	}

	wg.Wait()

	return vulnerabilities
}

func getLastUpdate(datastore database.Datastore) (time.Time, bool, error) {
	lastUpdateTSS, err := datastore.GetKeyValue(flagName)
	if err != nil {
		return time.Time{}, false, err
	}

	if lastUpdateTSS == "" {
		// This is the first update.
		return time.Time{}, true, nil
	}

	lastUpdateTS, err := strconv.ParseInt(lastUpdateTSS, 10, 64)
	if err != nil {
		return time.Time{}, false, err
	}

	return time.Unix(lastUpdateTS, 0).UTC(), false, nil
}

// doVulnerabilitiesNamespacing takes Vulnerabilities that don't have a Namespace and split them
// into multiple vulnerabilities that have a Namespace and only contains the FixedIn
// FeatureVersions corresponding to their Namespace.
//
// It helps simplifying the fetchers that share the same metadata about a Vulnerability regardless
// of their actual namespace (ie. same vulnerability information for every version of a distro).
func doVulnerabilitiesNamespacing(vulnerabilities []database.Vulnerability) []database.Vulnerability {
	vulnerabilitiesMap := make(map[string]*database.Vulnerability)

	for _, v := range vulnerabilities {
		featureVersions := v.FixedIn
		v.FixedIn = []database.FeatureVersion{}

		for _, fv := range featureVersions {
			index := fv.Feature.Namespace.Name + ":" + v.Name

			if vulnerability, ok := vulnerabilitiesMap[index]; !ok {
				newVulnerability := v
				newVulnerability.Namespace.Name = fv.Feature.Namespace.Name
				newVulnerability.FixedIn = []database.FeatureVersion{fv}

				vulnerabilitiesMap[index] = &newVulnerability
			} else {
				vulnerability.FixedIn = append(vulnerability.FixedIn, fv)
			}
		}
	}

	// Convert map into a slice.
	var response []database.Vulnerability
	for _, vulnerability := range vulnerabilitiesMap {
		response = append(response, *vulnerability)
	}

	return response
}
