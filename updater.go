// Copyright 2019 clair authors
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
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/pborman/uuid"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/vulnmdsrc"
	"github.com/coreos/clair/ext/vulnsrc"
	"github.com/coreos/clair/pkg/stopper"
	"github.com/coreos/clair/pkg/timeutil"
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
func RunUpdater(config *UpdaterConfig, datastore database.Datastore, st *stopper.Stopper) {
	defer st.End()

	// Do not run the updater if there is no config or if the interval is 0.
	if config == nil || config.Interval == 0 || len(config.EnabledUpdaters) == 0 {
		log.Info("updater service is disabled.")
		return
	}

	// Clean up any resources the updater left behind.
	defer func() {
		vulnmdsrc.CleanAll()
		vulnsrc.CleanAll()
		log.Info("updater service stopped")
	}()

	// Create a new unique identity for tracking who owns global locks.
	whoAmI := uuid.New()
	log.WithField("owner", whoAmI).Info("updater service started")

	sleepDuration := updaterSleepBetweenLoopsDuration
	for {
		// Determine if this is the first update and define the next update time.
		// The next update time is (last update time + interval) or now if this is the first update.
		nextUpdate := time.Now().UTC()
		lastUpdate, isFirstUpdate, err := GetLastUpdateTime(datastore)
		if err != nil {
			log.WithError(err).Error("an error occurred while getting the last update time")
			nextUpdate = nextUpdate.Add(config.Interval)
		}

		log.WithFields(log.Fields{
			"firstUpdate": isFirstUpdate,
			"nextUpdate":  nextUpdate,
		}).Debug("fetched last update time")
		if !isFirstUpdate {
			nextUpdate = lastUpdate.Add(config.Interval)
		}

		// If the next update timer is in the past, then try to update.
		if nextUpdate.Before(time.Now().UTC()) {
			// Attempt to get a lock on the update.
			log.Debug("attempting to obtain update lock")
			acquiredLock, lockExpiration := database.AcquireLock(datastore, updaterLockName, whoAmI, updaterLockDuration)
			if lockExpiration.IsZero() {
				// Any failures to acquire the lock should instantly expire.
				var instantExpiration time.Duration
				sleepDuration = instantExpiration
			}

			if acquiredLock {
				sleepDuration, err = updateWhileRenewingLock(datastore, whoAmI, isFirstUpdate, st)
				if err != nil {
					if err == errReceivedStopSignal {
						log.Debug("updater received stop signal")
						return
					}
					log.WithError(err).Debug("failed to acquired lock")
					sleepDuration = timeutil.ExpBackoff(sleepDuration, config.Interval)
				}
			} else {
				sleepDuration = updaterSleepBetweenLoopsDuration
			}
		} else {
			sleepDuration = time.Until(nextUpdate)
		}

		if stopped := timeutil.ApproxSleep(time.Now().Add(sleepDuration), st); stopped {
			return
		}
	}
}

var errReceivedStopSignal = errors.New("stopped")

func updateWhileRenewingLock(datastore database.Datastore, whoAmI string, isFirstUpdate bool, st *stopper.Stopper) (sleepDuration time.Duration, err error) {
	g, ctx := errgroup.WithContext(context.Background())
	g.Go(func() error {
		return update(ctx, datastore, isFirstUpdate)
	})

	g.Go(func() error {
		var refreshDuration = updaterLockRefreshDuration
		for {
			select {
			case <-time.After(timeutil.FractionalDuration(0.9, refreshDuration)):
				success, lockExpiration := database.ExtendLock(datastore, updaterLockName, whoAmI, updaterLockRefreshDuration)
				if !success {
					return errors.New("failed to extend lock")
				}
				refreshDuration = time.Until(lockExpiration)
			case <-ctx.Done():
				database.ReleaseLock(datastore, updaterLockName, whoAmI)
				return ctx.Err()
			}
		}
	})

	g.Go(func() error {
		select {
		case <-st.Chan():
			return errReceivedStopSignal
		case <-ctx.Done():
			return ctx.Err()
		}
	})

	err = g.Wait()
	return
}

// update fetches all the vulnerabilities from the registered fetchers, updates
// vulnerabilities, and updater flags, and logs notes from updaters.
func update(ctx context.Context, datastore database.Datastore, firstUpdate bool) error {
	defer setUpdaterDuration(time.Now())

	log.Info("updating vulnerabilities")

	// Fetch updates.
	success, vulnerabilities, flags, notes := fetchUpdates(ctx, datastore)

	namespaces, vulnerabilities := deduplicate(vulnerabilities)

	if err := database.PersistNamespacesAndCommit(datastore, namespaces); err != nil {
		log.WithError(err).Error("Unable to insert namespaces")
		return err
	}

	changes, err := updateVulnerabilities(ctx, datastore, vulnerabilities)

	defer func() {
		if err != nil {
			promUpdaterErrorsTotal.Inc()
		}
	}()

	if err != nil {
		log.WithError(err).Error("Unable to update vulnerabilities")
		return err
	}

	if !firstUpdate {
		err = createVulnerabilityNotifications(datastore, changes)
		if err != nil {
			log.WithError(err).Error("Unable to create notifications")
			return err
		}
	}

	err = updateUpdaterFlags(datastore, flags)
	if err != nil {
		log.WithError(err).Error("Unable to update updater flags")
		return err
	}

	for _, note := range notes {
		log.WithField("note", note).Warning("fetcher note")
	}
	promUpdaterNotesTotal.Set(float64(len(notes)))

	if success {
		err = setLastUpdateTime(datastore)
		if err != nil {
			log.WithError(err).Error("Unable to set last update time")
			return err
		}
	}

	log.Info("update finished")
	return nil
}

func deduplicate(vulns []database.VulnerabilityWithAffected) ([]database.Namespace, []database.VulnerabilityWithAffected) {
	// do vulnerability namespacing again to merge potentially duplicated
	// vulnerabilities from each updater.
	vulnerabilities := doVulnerabilitiesNamespacing(vulns)

	nsMap := map[database.Namespace]struct{}{}
	for _, vuln := range vulnerabilities {
		nsMap[vuln.Namespace] = struct{}{}
	}

	namespaces := make([]database.Namespace, 0, len(nsMap))
	for ns := range nsMap {
		namespaces = append(namespaces, ns)
	}

	return namespaces, vulnerabilities
}

func setUpdaterDuration(start time.Time) {
	promUpdaterDurationSeconds.Set(time.Since(start).Seconds())
}

// fetchUpdates asynchronously runs all of the enabled Updaters, aggregates
// their results, and appends metadata to the vulnerabilities found.
func fetchUpdates(ctx context.Context, datastore database.Datastore) (success bool, vulns []database.VulnerabilityWithAffected, flags map[string]string, notes []string) {
	flags = make(map[string]string)

	log.Info("fetching vulnerability updates")

	var mu sync.RWMutex
	g, ctx := errgroup.WithContext(ctx)
	for updaterName, updater := range vulnsrc.Updaters() {
		// Shadow the loop variables to avoid closing over the wrong thing.
		// See: https://golang.org/doc/faq#closures_and_goroutines
		updaterName := updaterName
		updater := updater

		g.Go(func() error {
			if !updaterEnabled(updaterName) {
				return nil
			}

			// TODO(jzelinskie): add context to Update()
			response, err := updater.Update(datastore)
			if err != nil {
				promUpdaterErrorsTotal.Inc()
				log.WithError(err).WithField("updater", updaterName).Error("an error occurred when fetching an update")
				return err
			}

			namespacedVulns := doVulnerabilitiesNamespacing(response.Vulnerabilities)

			mu.Lock()
			vulns = append(vulns, namespacedVulns...)
			notes = append(notes, response.Notes...)
			if response.FlagName != "" && response.FlagValue != "" {
				flags[response.FlagName] = response.FlagValue
			}
			mu.Unlock()

			return nil
		})
	}

	if err := g.Wait(); err == nil {
		success = true
	}

	vulns = addMetadata(ctx, datastore, vulns)

	return
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
	return status, addMetadata(context.TODO(), datastore, vulnerabilities), flags, notes
}

// addMetadata asynchronously updates a list of vulnerabilities with metadata
// from the vulnerability metadata sources.
func addMetadata(ctx context.Context, datastore database.Datastore, vulnerabilities []database.VulnerabilityWithAffected) []database.VulnerabilityWithAffected {
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

	g, ctx := errgroup.WithContext(ctx)
	for name, metadataAppender := range vulnmdsrc.Appenders() {
		// Shadow the loop variables to avoid closing over the wrong thing.
		// See: https://golang.org/doc/faq#closures_and_goroutines
		name := name
		metadataAppender := metadataAppender

		g.Go(func() error {
			// TODO(jzelinskie): add ctx to BuildCache()
			if err := metadataAppender.BuildCache(datastore); err != nil {
				promUpdaterErrorsTotal.Inc()
				log.WithError(err).WithField("appender", name).Error("an error occurred when fetching vulnerability metadata")
				return err
			}
			defer metadataAppender.PurgeCache()

			for i, vulnerability := range lockableVulnerabilities {
				metadataAppender.Append(vulnerability.Name, vulnerability.appendFunc)

				if i%10 == 0 {
					select {
					case <-ctx.Done():
						return nil
					default:
					}
				}
			}

			return nil
		})
	}

	g.Wait()

	return vulnerabilities
}

// GetLastUpdateTime retrieves the latest successful time of update and whether
// or not it's the first update.
func GetLastUpdateTime(datastore database.Datastore) (time.Time, bool, error) {
	lastUpdateTSS, ok, err := database.FindKeyValueAndRollback(datastore, updaterLastFlagName)
	if err != nil {
		return time.Time{}, false, err
	}

	if !ok {
		// This is the first update.
		return time.Time{}, true, nil
	}

	lastUpdateTS, err := strconv.ParseInt(lastUpdateTSS, 10, 64)
	if err != nil {
		panic(err)
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
			if fv.FeatureType == "" || fv.AffectedVersion == "" || fv.FeatureName == "" || fv.Namespace.Name == "" || fv.Namespace.VersionFormat == "" {
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

func updateUpdaterFlags(datastore database.Datastore, flags map[string]string) error {
	for key, value := range flags {
		if err := database.UpdateKeyValueAndCommit(datastore, key, value); err != nil {
			return err
		}
	}

	return nil
}

// setLastUpdateTime records the last successful date time in database.
func setLastUpdateTime(datastore database.Datastore) error {
	return database.UpdateKeyValueAndCommit(datastore, updaterLastFlagName, strconv.FormatInt(time.Now().UTC().Unix(), 10))
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

	return database.InsertVulnerabilityNotificationsAndCommit(datastore, notifications)
}

// updateVulnerabilities upserts unique vulnerabilities into the database and
// computes vulnerability changes.
func updateVulnerabilities(ctx context.Context, datastore database.Datastore, vulnerabilities []database.VulnerabilityWithAffected) ([]vulnerabilityChange, error) {
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

	oldVulnNullable, err := database.FindVulnerabilitiesAndRollback(datastore, ids)
	if err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
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

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
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

	log.Debugf("there are %d vulnerability changes", len(changes))
	return changes, database.UpdateVulnerabilitiesAndCommit(datastore, toRemove, toAdd)
}

func updaterEnabled(updaterName string) bool {
	for _, u := range EnabledUpdaters {
		if u == updaterName {
			return true
		}
	}
	return false
}
