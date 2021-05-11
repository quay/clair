package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"time"

	"github.com/google/uuid"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"

	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/matcher"
)

// indexerForTestMode configures a mock Indexer service for notifier test mode.
//
// in notifier test mode a notifier.Processor will request "indexer.AffectedManifest" with a
// set of vulnerabilities at which point we will return a mock affected vulnerability.
func indexerForTestMode(mock *indexer.Mock) {
	affectedManifests := func(ctx context.Context, vulns []claircore.Vulnerability) (*claircore.AffectedManifests, error) {
		if len(vulns) == 0 {
			return &claircore.AffectedManifests{}, nil
		}

		data := make([]byte, sha256.Size)
		_, err := rand.Read(data)
		if err != nil {
			return nil, err
		}
		digest, err := claircore.NewDigest("sha256", data)
		if err != nil {
			return nil, err
		}
		am := &claircore.AffectedManifests{
			Vulnerabilities: map[string]*claircore.Vulnerability{
				vulns[0].ID: &(vulns[0]),
			},
			VulnerableManifests: map[string][]string{
				digest.String(): {vulns[0].ID},
			},
		}
		return am, nil
	}
	mock.AffectedManifests_ = affectedManifests
}

// MatcherForTestMode configures a mock Matcher service for notifier test mode.
//
// in notifier test mode a notifier.Poller will request "matcher.LatestUpdateOperations" at which point
// a new UO pair will be smithed.
//
// next a notifier.Processor will request "matcher.UpdateOperations" and look for "test-updater" UOs in which
// the smithed pair will be returned.
//
// finally a notifier.Processor will request to "matcher.UpdateDiff" will be created where a mock added vulnerability
// will be returned.
func matcherForTestMode(mock *matcher.Mock) {
	latestUpdateOperations := func(context.Context, driver.UpdateKind) (map[string][]driver.UpdateOperation, error) {
		latest := driver.UpdateOperation{
			Ref:         uuid.New(),
			Updater:     "test-updater",
			Fingerprint: "test-fingerprint",
		}
		older := driver.UpdateOperation{
			Ref:         uuid.New(),
			Updater:     "test-updater",
			Fingerprint: "test-fingerprint",
		}
		mock.Lock()
		defer mock.Unlock()
		mock.TestUOs = map[string][]driver.UpdateOperation{
			"test-updater": []driver.UpdateOperation{latest, older},
		}
		m := map[string][]driver.UpdateOperation{
			latest.Updater: []driver.UpdateOperation{
				latest,
			},
		}
		return m, nil
	}
	updateOperations := func(context.Context, driver.UpdateKind, ...string) (map[string][]driver.UpdateOperation, error) {
		mock.Lock()
		defer mock.Unlock()
		m := map[string][]driver.UpdateOperation{}
		for k, v := range mock.TestUOs {
			m[k] = v
		}
		return m, nil
	}
	updateDiff := func(context.Context, uuid.UUID, uuid.UUID) (*driver.UpdateDiff, error) {
		v := claircore.Vulnerability{
			ID:                 "0",
			Updater:            "test-updater",
			Name:               "test-vulnerability",
			Description:        "this vulnerability indicates you are running the notifier in test mode.",
			Issued:             time.Now(),
			NormalizedSeverity: claircore.Unknown,
			FixedInVersion:     "",
		}
		mock.Lock()
		diff := driver.UpdateDiff{
			Cur:   mock.TestUOs["test-updater"][0],
			Prev:  mock.TestUOs["test-updater"][1],
			Added: []claircore.Vulnerability{v},
		}
		mock.Unlock()
		return &diff, nil
	}
	mock.LatestUpdateOperations_ = latestUpdateOperations
	mock.UpdateOperations_ = updateOperations
	mock.UpdateDiff_ = updateDiff
	return
}
