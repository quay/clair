package notifier

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/matcher"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
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
	ctx := context.TODO()
	e := Event{
		updater: testUpdater,
		uo:      processorUpdateOps[testUpdater][0],
	}
	mm := &matcher.Mock{
		UpdateDiff_: func(context.Context, uuid.UUID, uuid.UUID) (*driver.UpdateDiff, error) {
			return &driver.UpdateDiff{
				Added:   []claircore.Vulnerability{},
				Removed: []claircore.Vulnerability{},
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
	ctx := context.TODO()
	e := Event{
		updater: testUpdater,
		uo:      processorUpdateOps[testUpdater][0],
	}
	mm := &matcher.Mock{
		UpdateDiff_: func(context.Context, uuid.UUID, uuid.UUID) (*driver.UpdateDiff, error) {
			return &driver.UpdateDiff{
				Added:   []claircore.Vulnerability{},
				Removed: []claircore.Vulnerability{},
			}, nil
		},
	}
	im := &indexer.Mock{
		AffectedManifests_: func(ctx context.Context, vulns []claircore.Vulnerability) (*claircore.AffectedManifests, error) {
			return &claircore.AffectedManifests{}, fmt.Errorf("expected")
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
	ctx := context.TODO()
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
	ctx := context.TODO()
	e := Event{
		updater: testUpdater,
		uo:      processorUpdateOps[testUpdater][0],
	}
	mm := &matcher.Mock{
		UpdateDiff_: func(context.Context, uuid.UUID, uuid.UUID) (*driver.UpdateDiff, error) {
			return &driver.UpdateDiff{
				Added:   []claircore.Vulnerability{},
				Removed: []claircore.Vulnerability{},
			}, nil
		},
	}
	count := 0
	im := &indexer.Mock{
		AffectedManifests_: func(ctx context.Context, vulns []claircore.Vulnerability) (*claircore.AffectedManifests, error) {
			switch count {
			case 0:
				count++
				return affectedManifestsAdd, nil
			case 1:
				return affectedManifestsRemoved, nil
			default:
				return &claircore.AffectedManifests{}, fmt.Errorf("unexpected number of calls")
			}
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
