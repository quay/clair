// Copyright 2017 clair authors
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

package clair

import (
	"fmt"
	"math/rand"
	"strconv"
	"sync"
	"time"

	"github.com/pborman/uuid"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/vulnmdsrc"
	"github.com/coreos/clair/ext/vulnsrc"
	"github.com/coreos/clair/grafeas"
	"github.com/coreos/clair/pkg/stopper"
)

const (
	updaterLastFlagName              = "updater/last"
	updaterLockName                  = "updater"
	updaterLockDuration              = updaterLockRefreshDuration + time.Minute*2
	updaterLockRefreshDuration       = time.Minute * 8
	updaterSleepBetweenLoopsDuration = time.Minute
)

var (
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

	// EnabledUpdaters contains all updaters to be used for update.
	EnabledUpdaters []string
)

func init() {
	prometheus.MustRegister(promUpdaterErrorsTotal)
	prometheus.MustRegister(promUpdaterDurationSeconds)
	prometheus.MustRegister(promUpdaterNotesTotal)
}

// UpdaterConfig is the configuration for the Updater service.
type UpdaterConfig struct {
	EnabledUpdaters []string
	Interval        time.Duration
}

type vulnerabilityChange struct {
	old *database.VulnerabilityWithAffected
	new *database.VulnerabilityWithAffected
}

// RunUpdater begins a process that updates the vulnerability database at
// regular intervals.
func RunUpdater(config *UpdaterConfig, datastore database.Datastore, st *stopper.Stopper, g grafeas.Grafeas) {
	defer st.End()

	// Do not run the updater if there is no config or if the interval is 0.
	if config == nil || config.Interval == 0 || len(config.EnabledUpdaters) == 0 {
		log.Info("updater service is disabled.")
		return
	}

	whoAmI := uuid.New()
	log.WithField("lock identifier", whoAmI).Info("updater service started")

	for {
		var stop bool

		// Determine if this is the first update and define the next update time.
		// The next update time is (last update time + interval) or now if this is the first update.
		nextUpdate := time.Now().UTC()
		lastUpdate, firstUpdate, err := GetLastUpdateTime(datastore)
		if err != nil {
			log.WithError(err).Error("an error occurred while getting the last update time")
			nextUpdate = nextUpdate.Add(config.Interval)
		} else if !firstUpdate {
			nextUpdate = lastUpdate.Add(config.Interval)
		}

		// If the next update timer is in the past, then try to update.
		if nextUpdate.Before(time.Now().UTC()) {
			// Attempt to get a lock on the the update.
			log.Debug("attempting to obtain update lock")
			hasLock, hasLockUntil := lock(datastore, updaterLockName, whoAmI, updaterLockDuration, false)
			if hasLock {
				// Launch update in a new go routine.
				doneC := make(chan bool, 1)
				go func() {
					update(datastore, firstUpdate)
					doneC <- true
				}()

				for done := false; !done && !stop; {
					select {
					case <-doneC:
						done = true
					case <-time.After(updaterLockRefreshDuration):
						// Refresh the lock until the update is done.
						lock(datastore, updaterLockName, whoAmI, updaterLockDuration, true)
					case <-st.Chan():
						stop = true
					}
				}

				g.Export(datastore)

				// Unlock the updater.
				unlock(datastore, updaterLockName, whoAmI)

				if stop {
					break
				}

				// Sleep for a short duration to prevent pinning the CPU on a
				// consistent failure.
				if stopped := sleepUpdater(time.Now().Add(updaterSleepBetweenLoopsDuration), st); stopped {
					break
				}
				continue
			} else {
				lockOwner, lockExpiration, ok, err := findLock(datastore, updaterLockName)
				if !ok || err != nil {
					log.Debug("update lock is already taken")
					nextUpdate = hasLockUntil
				} else {
					log.WithFields(log.Fields{"lock owner": lockOwner, "lock expiration": lockExpiration}).Debug("update lock is already taken")
					nextUpdate = lockExpiration
				}
			}
		}

		if stopped := sleepUpdater(nextUpdate, st); stopped {
			break
		}
	}

	// Clean resources.
	for _, appenders := range vulnmdsrc.Appenders() {
		appenders.Clean()
	}
	for _, updaters := range vulnsrc.Updaters() {
		updaters.Clean()
	}

	log.Info("updater service stopped")
}

// sleepUpdater sleeps the updater for an approximate duration, but remains
// able to be cancelled by a stopper.
func sleepUpdater(approxWakeup time.Time, st *stopper.Stopper) (stopped bool) {
	waitUntil := approxWakeup.Add(time.Duration(rand.ExpFloat64()/0.5) * time.Second)
	log.WithField("scheduled time", waitUntil).Debug("updater sleeping")
	if !waitUntil.Before(time.Now().UTC()) {
		if !st.Sleep(waitUntil.Sub(time.Now())) {
			return true
		}
	}
	return false
}

// update fetches all the vulnerabilities from the registered fetchers, updates
// vulnerabilities, and updater flags, and logs notes from updaters.
func update(datastore database.Datastore, firstUpdate bool) {
	defer setUpdaterDuration(time.Now())

	log.Info("updating vulnerabilities")

	// Fetch updates.
	success, vulnerabilities, flags, notes := fetch(datastore)

	// do vulnerability namespacing again to merge potentially duplicated
	// vulnerabilities from each updater.
	vulnerabilities = doVulnerabilitiesNamespacing(vulnerabilities)

	// deduplicate fetched namespaces and store them into database.
	nsMap := map[database.Namespace]struct{}{}
	for _, vuln := range vulnerabilities {
		nsMap[vuln.Namespace] = struct{}{}
	}

	namespaces := make([]database.Namespace, 0, len(nsMap))
	for ns := range nsMap {
		namespaces = append(namespaces, ns)
	}

	if err := persistNamespaces(datastore, namespaces); err != nil {
		log.WithError(err).Error("Unable to insert namespaces")
		return
	}

	changes, err := updateVulnerabilities(datastore, vulnerabilities)

	defer func() {
		if err != nil {
			promUpdaterErrorsTotal.Inc()
		}
	}()

	if err != nil {
		log.WithError(err).Error("Unable to update vulnerabilities")
		return
	}

	if !firstUpdate {
		err = createVulnerabilityNotifications(datastore, changes)
		if err != nil {
			log.WithError(err).Error("Unable to create notifications")
			return
		}
	}

	err = updateUpdaterFlags(datastore, flags)
	if err != nil {
		log.WithError(err).Error("Unable to update updater flags")
		return
	}

	for _, note := range notes {
		log.WithField("note", note).Warning("fetcher note")
	}
	promUpdaterNotesTotal.Set(float64(len(notes)))

	if success {
		err = setLastUpdateTime(datastore)
		if err != nil {
			log.WithError(err).Error("Unable to set last update time")
			return
		}
	}

	log.Info("update finished")
}

func setUpdaterDuration(start time.Time) {
	promUpdaterDurationSeconds.Set(time.Since(start).Seconds())
}

// fetch get data from the registered fetchers, in parallel.
func fetch(datastore database.Datastore) (bool, []database.VulnerabilityWithAffected, map[string]string, []string) {
	var vulnerabilities []database.VulnerabilityWithAffected
	var notes []string
	status := true
	flags := make(map[string]string)

	// Fetch updates in parallel.
	log.Info("fetching vulnerability updates")
	var responseC = make(chan *vulnsrc.UpdateResponse, 0)
	numUpdaters := 0
	for n, u := range vulnsrc.Updaters() {
		if !updaterEnabled(n) {
			continue
		}
		numUpdaters++
		go func(name string, u vulnsrc.Updater) {
			response, err := u.Update(datastore)
			if err != nil {
				promUpdaterErrorsTotal.Inc()
				log.WithError(err).WithField("updater name", name).Error("an error occurred when fetching update")
				status = false
				responseC <- nil
				return
			}

			responseC <- &response
			log.WithField("updater name", name).Info("finished fetching")
		}(n, u)
	}

	// Collect results of updates.
	for i := 0; i < numUpdaters; i++ {
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

// Add metadata to the specified vulnerabilities using the registered
// MetadataFetchers, in parallel.
func addMetadata(datastore database.Datastore, vulnerabilities []database.VulnerabilityWithAffected) []database.VulnerabilityWithAffected {
	if len(vulnmdsrc.Appenders()) == 0 || len(vulnerabilities) == 0 {
		return vulnerabilities
	}

	log.Info("adding metadata to vulnerabilities")

	// Add a mutex to each vulnerability to ensure that only one appender at a
	// time can modify the vulnerability's Metadata map.
	lockableVulnerabilities := make([]*lockableVulnerability, 0, len(vulnerabilities))
	for i := 0; i < len(vulnerabilities); i++ {
		lockableVulnerabilities = append(lockableVulnerabilities, &lockableVulnerability{
			VulnerabilityWithAffected: &vulnerabilities[i],
		})
	}

	var wg sync.WaitGroup
	wg.Add(len(vulnmdsrc.Appenders()))

	for n, a := range vulnmdsrc.Appenders() {
		go func(name string, appender vulnmdsrc.Appender) {
			defer wg.Done()

			// Build up a metadata cache.
			if err := appender.BuildCache(datastore); err != nil {
				promUpdaterErrorsTotal.Inc()
				log.WithError(err).WithField("appender name", name).Error("an error occurred when loading metadata fetcher")
				return
			}

			// Append vulnerability metadata  to each vulnerability.
			for _, vulnerability := range lockableVulnerabilities {
				appender.Append(vulnerability.Name, vulnerability.appendFunc)
			}

			// Purge the metadata cache.
			appender.PurgeCache()
		}(n, a)
	}

	wg.Wait()

	return vulnerabilities
}

// GetLastUpdateTime retrieves the latest successful time of update and whether
// or not it's the first update.
func GetLastUpdateTime(datastore database.Datastore) (time.Time, bool, error) {
	tx, err := datastore.Begin()
	if err != nil {
		return time.Time{}, false, err
	}
	defer tx.Rollback()

	lastUpdateTSS, ok, err := tx.FindKeyValue(updaterLastFlagName)
	if err != nil {
		return time.Time{}, false, err
	}

	if !ok {
		// This is the first update.
		return time.Time{}, true, nil
	}

	lastUpdateTS, err := strconv.ParseInt(lastUpdateTSS, 10, 64)
	if err != nil {
		return time.Time{}, false, err
	}

	return time.Unix(lastUpdateTS, 0).UTC(), false, nil
}

type lockableVulnerability struct {
	*database.VulnerabilityWithAffected
	sync.Mutex
}

func (lv *lockableVulnerability) appendFunc(metadataKey string, metadata interface{}, severity database.Severity) {
	lv.Lock()
	defer lv.Unlock()

	// If necessary, initialize the metadata map for the vulnerability.
	if lv.Metadata == nil {
		lv.Metadata = make(map[string]interface{})
	}

	// Append the metadata.
	lv.Metadata[metadataKey] = metadata

	// If necessary, provide a severity for the vulnerability.
	if lv.Severity == database.UnknownSeverity {
		lv.Severity = severity
	}
}

// doVulnerabilitiesNamespacing takes Vulnerabilities that don't have a
// Namespace and split them into multiple vulnerabilities that have a Namespace
// and only contains the Affected Features corresponding to their
// Namespace.
//
// It helps simplifying the fetchers that share the same metadata about a
// Vulnerability regardless of their actual namespace (ie. same vulnerability
// information for every version of a distro).
//
// It also validates the vulnerabilities fetched from updaters. If any
// vulnerability is mal-formated, the updater process will continue but will log
// warning.
func doVulnerabilitiesNamespacing(vulnerabilities []database.VulnerabilityWithAffected) []database.VulnerabilityWithAffected {
	vulnerabilitiesMap := make(map[string]*database.VulnerabilityWithAffected)

	for _, v := range vulnerabilities {
		namespacedFeatures := v.Affected
		v.Affected = []database.AffectedFeature{}

		for _, fv := range namespacedFeatures {
			// validate vulnerabilities, throw out the invalid vulnerabilities
			if fv.AffectedVersion == "" || fv.FeatureName == "" || fv.Namespace.Name == "" || fv.Namespace.VersionFormat == "" {
				log.WithFields(log.Fields{
					"Name":             fv.FeatureName,
					"Affected Version": fv.AffectedVersion,
					"Namespace":        fv.Namespace.Name + ":" + fv.Namespace.VersionFormat,
				}).Warn("Mal-formated affected feature (skipped)")
				continue
			}
			index := fv.Namespace.Name + ":" + v.Name

			if vulnerability, ok := vulnerabilitiesMap[index]; !ok {
				newVulnerability := v
				newVulnerability.Namespace = fv.Namespace
				newVulnerability.Affected = []database.AffectedFeature{fv}

				vulnerabilitiesMap[index] = &newVulnerability
			} else {
				vulnerability.Affected = append(vulnerability.Affected, fv)
			}
		}
	}

	// Convert map into a slice.
	var response []database.VulnerabilityWithAffected
	for _, v := range vulnerabilitiesMap {
		// throw out invalid vulnerabilities.
		if v.Name == "" || !v.Severity.Valid() || v.Namespace.Name == "" || v.Namespace.VersionFormat == "" {
			log.WithFields(log.Fields{
				"Name":      v.Name,
				"Severity":  v.Severity,
				"Namespace": v.Namespace.Name + ":" + v.Namespace.VersionFormat,
			}).Warning("Vulnerability is mal-formatted")
			continue
		}
		response = append(response, *v)
	}

	return response
}

func findLock(datastore database.Datastore, updaterLockName string) (string, time.Time, bool, error) {
	tx, err := datastore.Begin()
	if err != nil {
		log.WithError(err).Error()
	}
	defer tx.Rollback()
	return tx.FindLock(updaterLockName)
}

// updateUpdaterFlags updates the flags specified by updaters, every transaction
// is independent of each other.
func updateUpdaterFlags(datastore database.Datastore, flags map[string]string) error {
	for key, value := range flags {
		tx, err := datastore.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		err = tx.UpdateKeyValue(key, value)
		if err != nil {
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// setLastUpdateTime records the last successful date time in database.
func setLastUpdateTime(datastore database.Datastore) error {
	tx, err := datastore.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	err = tx.UpdateKeyValue(updaterLastFlagName, strconv.FormatInt(time.Now().UTC().Unix(), 10))
	if err != nil {
		return err
	}
	return tx.Commit()
}

// isVulnerabilityChange compares two vulnerabilities by their severity and
// affected features, and return true if they are different.
func isVulnerabilityChanged(a *database.VulnerabilityWithAffected, b *database.VulnerabilityWithAffected) bool {
	if a == b {
		return false
	} else if a != nil && b != nil && a.Severity == b.Severity && len(a.Affected) == len(b.Affected) {
		checked := map[string]bool{}
		for _, affected := range a.Affected {
			checked[affected.Namespace.Name+":"+affected.FeatureName] = false
		}

		for _, affected := range b.Affected {
			key := affected.Namespace.Name + ":" + affected.FeatureName
			if visited, ok := checked[key]; !ok || visited {
				return true
			}
			checked[key] = true
		}
		return false
	}
	return true
}

// findVulnerabilityChanges finds vulnerability changes from old
// vulnerabilities to new vulnerabilities.
// old and new vulnerabilities should be unique.
func findVulnerabilityChanges(old []database.VulnerabilityWithAffected, new []database.VulnerabilityWithAffected) ([]vulnerabilityChange, error) {
	changes := map[database.VulnerabilityID]vulnerabilityChange{}
	for i, vuln := range old {
		key := database.VulnerabilityID{
			Name:      vuln.Name,
			Namespace: vuln.Namespace.Name,
		}

		if _, ok := changes[key]; ok {
			return nil, fmt.Errorf("duplicated old vulnerability")
		}
		changes[key] = vulnerabilityChange{old: &old[i]}
	}

	for i, vuln := range new {
		key := database.VulnerabilityID{
			Name:      vuln.Name,
			Namespace: vuln.Namespace.Name,
		}

		if change, ok := changes[key]; ok {
			if isVulnerabilityChanged(change.old, &vuln) {
				change.new = &new[i]
				changes[key] = change
			} else {
				delete(changes, key)
			}
		} else {
			changes[key] = vulnerabilityChange{new: &new[i]}
		}
	}

	vulnChange := make([]vulnerabilityChange, 0, len(changes))
	for _, change := range changes {
		vulnChange = append(vulnChange, change)
	}
	return vulnChange, nil
}

// createVulnerabilityNotifications makes notifications out of vulnerability
// changes and insert them into database.
func createVulnerabilityNotifications(datastore database.Datastore, changes []vulnerabilityChange) error {
	log.WithField("count", len(changes)).Debug("creating vulnerability notifications")
	if len(changes) == 0 {
		return nil
	}

	tx, err := datastore.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	notifications := make([]database.VulnerabilityNotification, 0, len(changes))
	for _, change := range changes {
		var oldVuln, newVuln *database.Vulnerability
		if change.old != nil {
			oldVuln = &change.old.Vulnerability
		}

		if change.new != nil {
			newVuln = &change.new.Vulnerability
		}

		notifications = append(notifications, database.VulnerabilityNotification{
			NotificationHook: database.NotificationHook{
				Name:    uuid.New(),
				Created: time.Now(),
			},
			Old: oldVuln,
			New: newVuln,
		})
	}

	if err := tx.InsertVulnerabilityNotifications(notifications); err != nil {
		return err
	}

	return tx.Commit()
}

// updateVulnerabilities upserts unique vulnerabilities into the database and
// computes vulnerability changes.
func updateVulnerabilities(datastore database.Datastore, vulnerabilities []database.VulnerabilityWithAffected) ([]vulnerabilityChange, error) {
	log.WithField("count", len(vulnerabilities)).Debug("updating vulnerabilities")
	if len(vulnerabilities) == 0 {
		return nil, nil
	}

	ids := make([]database.VulnerabilityID, 0, len(vulnerabilities))
	for _, vuln := range vulnerabilities {
		ids = append(ids, database.VulnerabilityID{
			Name:      vuln.Name,
			Namespace: vuln.Namespace.Name,
		})
	}

	tx, err := datastore.Begin()
	if err != nil {
		return nil, err
	}

	defer tx.Rollback()
	oldVulnNullable, err := tx.FindVulnerabilities(ids)
	if err != nil {
		return nil, err
	}

	oldVuln := []database.VulnerabilityWithAffected{}
	for _, vuln := range oldVulnNullable {
		if vuln.Valid {
			oldVuln = append(oldVuln, vuln.VulnerabilityWithAffected)
		}
	}

	changes, err := findVulnerabilityChanges(oldVuln, vulnerabilities)
	if err != nil {
		return nil, err
	}

	toRemove := []database.VulnerabilityID{}
	toAdd := []database.VulnerabilityWithAffected{}
	for _, change := range changes {
		if change.old != nil {
			toRemove = append(toRemove, database.VulnerabilityID{
				Name:      change.old.Name,
				Namespace: change.old.Namespace.Name,
			})
		}

		if change.new != nil {
			toAdd = append(toAdd, *change.new)
		}
	}

	log.WithField("count", len(toRemove)).Debug("marking vulnerabilities as outdated")
	if err := tx.DeleteVulnerabilities(toRemove); err != nil {
		return nil, err
	}

	log.WithField("count", len(toAdd)).Debug("inserting new vulnerabilities")
	if err := tx.InsertVulnerabilities(toAdd); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return changes, nil
}

func updaterEnabled(updaterName string) bool {
	for _, u := range EnabledUpdaters {
		if u == updaterName {
			return true
		}
	}
	return false
}
