package notifier

import (
	"context"
	"fmt"
	"sort"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/zlog"

	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/matcher"
)

var (
	vulnAdd = &claircore.Vulnerability{
		ID:          "0",
		Name:        "added vulnerability",
		Description: "a vulnerability added",
	}
	vulnRemoved = &claircore.Vulnerability{
		ID:          "1",
		Name:        "removed vulnerability",
		Description: "a vulnerability removed",
	}
	manifestAdd          = `sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef`
	manifestRemoved      = `sha256:fc92eec5cac70b0c324cec2933cd7db1c0eae7c9e2649e42d02e77eb6da0d15f`
	affectedManifestsAdd = &claircore.AffectedManifests{
		Vulnerabilities: map[string]*claircore.Vulnerability{
			vulnAdd.ID: vulnAdd,
		},
		VulnerableManifests: map[string][]string{
			manifestAdd: {vulnAdd.ID},
		},
	}
	affectedManifestsRemoved = &claircore.AffectedManifests{
		Vulnerabilities: map[string]*claircore.Vulnerability{
			vulnRemoved.ID: vulnRemoved,
		},
		VulnerableManifests: map[string][]string{
			manifestRemoved: {vulnRemoved.ID},
		},
	}
	notifications = []Notification{
		{
			Manifest: claircore.MustParseDigest(manifestAdd),
			Reason:   Added,
			Vulnerability: VulnSummary{
				Description: affectedManifestsAdd.Vulnerabilities[vulnAdd.ID].Description,
				Name:        affectedManifestsAdd.Vulnerabilities[vulnAdd.ID].Name,
				Severity:    claircore.Unknown.String(),
			},
		},
		{
			Manifest: claircore.MustParseDigest(manifestRemoved),
			Reason:   Removed,
			Vulnerability: VulnSummary{
				Description: affectedManifestsRemoved.Vulnerabilities[vulnRemoved.ID].Description,
				Name:        affectedManifestsRemoved.Vulnerabilities[vulnRemoved.ID].Name,
				Severity:    claircore.Unknown.String(),
			},
		},
	}
)

func TestProcessCreate(t *testing.T) {
	t.Run("Create", testProcessorCreate)
	t.Run("MatcherErr", testProcessorMatcherErr)
	t.Run("IndexerErr", testProcessorIndexerErr)
	t.Run("StoreErr", testProcessorStoreErr)
}

// testProcessorStoreErr confirms create fails when the store is not
// available
func testProcessorStoreErr(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)
	e := Event{
		updater: testUpdater,
		uo:      processorUpdateOps[testUpdater][0],
	}
	mm := &matcher.Mock{
		UpdateDiff_: func(context.Context, uuid.UUID, uuid.UUID) (*driver.UpdateDiff, error) {
			return &driver.UpdateDiff{
				Added:   []claircore.Vulnerability{*vulnAdd},
				Removed: []claircore.Vulnerability{*vulnRemoved},
			}, nil
		},
	}
	im := &indexer.Mock{
		AffectedManifests_: func(ctx context.Context, vulns []claircore.Vulnerability) (*claircore.AffectedManifests, error) {
			// needs to be populated.
			// create method needs at least one affected manifest
			// for the code path to invoke store.PutNotifications()
			return affectedManifestsAdd, nil
		},
	}
	// perform bulk of checks in this mock method.
	sm := &MockStore{
		PutNotifications_: func(_ context.Context, _ PutOpts) error {
			return fmt.Errorf("expected")
		},
	}

	p := Processor{
		store:   sm,
		indexer: im,
		matcher: mm,
	}

	err := p.create(ctx, e, uuid.Nil)
	if err == nil {
		t.Fatalf("expected err")
	}
}

// testProcessorIndexerErr confirms create fails when the indexer is not
// available
func testProcessorIndexerErr(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)
	e := Event{
		updater: testUpdater,
		uo:      processorUpdateOps[testUpdater][0],
	}
	mm := &matcher.Mock{
		UpdateDiff_: func(context.Context, uuid.UUID, uuid.UUID) (*driver.UpdateDiff, error) {
			return &driver.UpdateDiff{
				Added:   []claircore.Vulnerability{*vulnAdd},
				Removed: []claircore.Vulnerability{*vulnRemoved},
			}, nil
		},
	}
	im := &indexer.Mock{
		AffectedManifests_: func(ctx context.Context, vulns []claircore.Vulnerability) (*claircore.AffectedManifests, error) {
			return nil, fmt.Errorf("expected")
		},
	}
	// perform bulk of checks in this mock method.
	sm := &MockStore{
		PutNotifications_: func(ctx context.Context, opts PutOpts) error {
			return nil
		},
	}

	p := Processor{
		store:   sm,
		indexer: im,
		matcher: mm,
	}

	err := p.create(ctx, e, uuid.Nil)
	if err == nil {
		t.Fatalf("expected err")
	}
}

// testProcessorMatcherErr confirms create fails when the matcher is not
// available
func testProcessorMatcherErr(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)
	e := Event{
		updater: testUpdater,
		uo:      processorUpdateOps[testUpdater][0],
	}
	mm := &matcher.Mock{
		UpdateDiff_: func(context.Context, uuid.UUID, uuid.UUID) (*driver.UpdateDiff, error) {
			return nil, fmt.Errorf("expected")
		},
	}
	im := &indexer.Mock{
		AffectedManifests_: func(ctx context.Context, vulns []claircore.Vulnerability) (*claircore.AffectedManifests, error) {
			return &claircore.AffectedManifests{}, nil
		},
	}
	// perform bulk of checks in this mock method.
	sm := &MockStore{
		PutNotifications_: func(ctx context.Context, opts PutOpts) error {
			return nil
		},
	}

	p := Processor{
		store:   sm,
		indexer: im,
		matcher: mm,
	}

	err := p.create(ctx, e, uuid.Nil)
	if err == nil {
		t.Fatalf("expected err")
	}
}

// testProcessorCreate confirms notifications are created correctly.
func testProcessorCreate(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)
	e := Event{
		updater: testUpdater,
		uo:      processorUpdateOps[testUpdater][0],
	}
	mm := &matcher.Mock{
		UpdateDiff_: func(context.Context, uuid.UUID, uuid.UUID) (*driver.UpdateDiff, error) {
			return &driver.UpdateDiff{
				Added:   []claircore.Vulnerability{*vulnAdd},
				Removed: []claircore.Vulnerability{*vulnRemoved},
			}, nil
		},
	}
	count := uint64(0)
	im := &indexer.Mock{
		AffectedManifests_: func(ctx context.Context, vulns []claircore.Vulnerability) (*claircore.AffectedManifests, error) {
			if atomic.LoadUint64(&count) > 1 {
				return nil, fmt.Errorf("unexpected number of calls")
			}
			atomic.AddUint64(&count, 1)
			switch vulns[0].ID {
			case "0":
				return affectedManifestsAdd, nil
			case "1":
				return affectedManifestsRemoved, nil
			}
			return nil, fmt.Errorf("unexpected call")
		},
	}
	// perform bulk of checks in this mock method.
	sm := &MockStore{
		PutNotifications_: func(ctx context.Context, opts PutOpts) error {
			if opts.Updater != e.updater {
				t.Fatalf("got: %s, wanted: %s", opts.Updater, testUpdater)
			}
			if opts.UpdateID != e.uo.Ref {
				t.Fatalf("got: %v, want: %v", opts.UpdateID, e.uo.Ref)
			}
			if opts.NotificationID == uuid.Nil {
				t.Fatalf("malformed notification id: %v", opts.NotificationID)
			}
			// Need some sort of stable order here:
			sort.Slice(opts.Notifications, func(i, j int) bool {
				return opts.Notifications[i].Reason < opts.Notifications[j].Reason
			})
			if !cmp.Equal(opts.Notifications, notifications, cmpopts.IgnoreUnexported(claircore.Digest{})) {
				t.Fatalf("%v", cmp.Diff(opts.Notifications, notifications, cmpopts.IgnoreUnexported(claircore.Digest{})))
			}

			return nil
		},
	}

	p := Processor{
		store:   sm,
		indexer: im,
		matcher: mm,
	}

	err := p.create(ctx, e, uuid.Nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
}
