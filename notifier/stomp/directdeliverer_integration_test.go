package stomp

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/quay/claircore"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/zlog"
	"golang.org/x/sync/errgroup"

	"github.com/quay/clair/v4/notifier"
)

// TestDirectDeliverer confirms delivery of notifications directly
// to the STOMP queue with rollup works correctly.
func TestDirectDeliverer(t *testing.T) {
	integration.Skip(t)
	// test start
	table := []struct {
		name   string
		rollup int
		notes  int
	}{
		{
			name:   "check 0",
			rollup: 0,
			notes:  1,
		},
		{
			name:   "check 1",
			rollup: 1,
			notes:  5,
		},
		{
			name:   "check rollup overflow",
			rollup: 10,
			notes:  5,
		},
		{
			name:   "check odds",
			rollup: 3,
			notes:  7,
		},
		{
			name:   "check odds rollup",
			rollup: 3,
			notes:  8,
		},
		{
			name:   "check odds notes",
			rollup: 4,
			notes:  7,
		},
		{
			name:   "check large",
			rollup: 100,
			notes:  1000,
		},
	}

	uri := os.Getenv("STOMP_CONNECTION_STRING")
	if uri == "" {
		uri = defaultStompBrokerURI
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			ctx := zlog.Test(context.Background(), t)
			// deliverer test
			conf := Config{
				Direct:      true,
				Rollup:      tt.rollup,
				Destination: "notifications",
				URIs: []string{
					// give a few bogus URIs to confirm failover mechanisms are working
					"nohost1:5672/",
					"nohost2:5672/",
					"nohost3:5672/",
					uri,
				},
			}

			noteID := uuid.New()
			notes := make([]notifier.Notification, 0, tt.notes)
			for i := 0; i < tt.notes; i++ {
				notes = append(notes, notifier.Notification{
					ID:       uuid.New(),
					Manifest: claircore.MustParseDigest("sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a"),
					Reason:   notifier.Added,
					Vulnerability: notifier.VulnSummary{
						Description: fmt.Sprintf("test-vuln-%d", i),
					},
				})
			}

			// test parallel usage
			g := errgroup.Group{}
			for i := 0; i < 4; i++ {
				g.Go(func() error {
					d, err := NewDirectDeliverer(conf)
					if err != nil {
						return fmt.Errorf("could not create deliverer: %v", err)
					}
					err = d.Notifications(ctx, notes)
					if err != nil {
						return fmt.Errorf("failed to provide notifications to direct deliverer: %v", err)
					}
					// will error if message cannot be delivered to broker
					err = d.Deliver(ctx, noteID)
					if err != nil {
						return fmt.Errorf("failed to deliver message: %v", err)
					}
					return nil
				})
			}
			if err := g.Wait(); err != nil {
				t.Fatalf("test failed: %v", err)
			}
		})
	}
}
