package notifier

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/zlog"

	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/matcher"
)

func TestNotificationSummary(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)

	// This is a bunch of supporting data structures.
	updater := uuid.New().String()
	e := Event{
		updater: updater,
		uo: driver.UpdateOperation{
			Ref:     uuid.New(),
			Updater: updater,
		},
	}
	manifest := "sha256:8d502da610b3c153d5aedaaf5323c0d49f61401d4791b4b1ffe9e36c6cbe09a0"
	vs := []claircore.Vulnerability{
		{ID: "🖳", Name: "uncool vulnerability"},
		{ID: "☃", Name: "cool vulnerability", NormalizedSeverity: claircore.Critical},
	}
	am := &claircore.AffectedManifests{
		Vulnerabilities: map[string]*claircore.Vulnerability{
			"☃": &vs[0],
			"🖳": &vs[1],
		},
		VulnerableManifests: map[string][]string{},
	}
	for _, v := range vs {
		am.VulnerableManifests[manifest] = append(am.VulnerableManifests[manifest], v.ID)
	}
	p := Processor{
		matcher: &matcher.Mock{
			UpdateDiff_: func(_ context.Context, prev, _ uuid.UUID) (*driver.UpdateDiff, error) {
				if got, want := prev, uuid.Nil; got != want {
					t.Errorf("got: %v, want: %v", got, want)
				}
				return &driver.UpdateDiff{
					Added:   vs,
					Removed: []claircore.Vulnerability{},
				}, nil
			},
		},
		indexer: &indexer.Mock{
			AffectedManifests_: func(_ context.Context, vs []claircore.Vulnerability) (*claircore.AffectedManifests, error) {
				if len(vs) > 0 {
					// Needs at least one affected manifest
					// for the code path to invoke store.PutNotifications()
					return am, nil
				}
				return &claircore.AffectedManifests{}, nil
			},
		},
	}

	// Enable summarization, set the check function.
	p.NoSummary = false
	p.store = &MockStore{
		PutNotifications_: func(_ context.Context, o PutOpts) error {
			t.Logf("got notification ID: %v", o.NotificationID)
			for _, n := range o.Notifications {
				t.Logf("manifest(%v): %v %v", n.Manifest, n.Reason, n.Vulnerability.Name)
			}
			if got, want := len(o.Notifications), 1; got != want {
				t.Errorf("got: %d, want: %d", got, want)
			}
			if got, want := vs[1].Name, o.Notifications[0].Vulnerability.Name; got != want {
				t.Errorf("got: %s, want: %s", got, want)
			}
			return nil
		},
	}
	if err := p.create(ctx, e, uuid.Nil); err != nil {
		t.Error(err)
	}

	// Disable summarization, swap the check function, and run again.
	p.NoSummary = true
	p.store = &MockStore{
		PutNotifications_: func(_ context.Context, o PutOpts) error {
			t.Logf("got notification ID: %v", o.NotificationID)
			for _, n := range o.Notifications {
				t.Logf("manifest(%v): %v %v", n.Manifest, n.Reason, n.Vulnerability.Name)
			}
			if got, want := len(o.Notifications), len(vs); got != want {
				t.Errorf("got: %d, want: %d", got, want)
			}
			return nil
		},
	}
	if err := p.create(ctx, e, uuid.Nil); err != nil {
		t.Error(err)
	}
}
