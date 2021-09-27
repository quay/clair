package stomp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/go-stomp/stomp"
	"github.com/google/uuid"
	"github.com/quay/claircore"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/zlog"
	"golang.org/x/sync/errgroup"

	"github.com/quay/clair/v4/config"
	"github.com/quay/clair/v4/notifier"
)

// TestDirectDeliverer confirms delivery of notifications directly
// to the STOMP queue with rollup works correctly.
func TestDirectDeliverer(t *testing.T) {
	integration.Skip(t)
	// test start
	table := []struct {
		name         string
		rollup       int
		notes        int
		expectedMsgs int
	}{
		{
			name:         "check 0",
			rollup:       0,
			notes:        1,
			expectedMsgs: 1,
		},
		{
			name:         "check 1",
			rollup:       1,
			notes:        5,
			expectedMsgs: 5,
		},
		{
			name:         "check rollup overflow",
			rollup:       10,
			notes:        5,
			expectedMsgs: 1,
		},
		{
			name:         "check odds",
			rollup:       3,
			notes:        7,
			expectedMsgs: 3,
		},
		{
			name:         "check odds rollup",
			rollup:       3,
			notes:        8,
			expectedMsgs: 3,
		},
		{
			name:         "check odds notes",
			rollup:       4,
			notes:        7,
			expectedMsgs: 2,
		},
		{
			name:         "check large",
			rollup:       100,
			notes:        1000,
			expectedMsgs: 10,
		},
	}

	uri := os.Getenv("STOMP_CONNECTION_STRING")
	if uri == "" {
		uri = defaultStompBrokerURI
	}
	for _, tt := range table {
		queue := uuid.New().String()
		t.Run(tt.name, func(t *testing.T) {
			ctx := zlog.Test(context.Background(), t)
			// deliverer test
			conf := config.STOMP{
				Direct:      true,
				Rollup:      tt.rollup,
				Destination: queue,
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
					d, err := NewDirectDeliverer(&conf)
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

			// create consumer
			conn, err := stomp.Dial("tcp", uri)
			if err != nil {
				t.Fatalf("failed to connect to broker at %s: %v", uri, err)
			}
			defer conn.Disconnect()

			sub, err := conn.Subscribe(queue, stomp.AckClient)
			if err != nil {
				t.Fatalf("failed to subscribe to %s: %v", queue, err)
			}
			defer sub.Unsubscribe()

			// read messages
			totalExpectedMsgs := tt.expectedMsgs * 4
			for i := 0; i < totalExpectedMsgs; i++ {
				m, err := sub.Read()
				if err != nil {
					t.Fatalf("cannot read msg from subscription: %v", err)
				}
				if m.ContentType != "application/json" {
					t.Errorf("msg content type mismatch: expected %s, got %s", "application/json", m.ContentType)
				}
				var msgBody []notifier.Notification
				if err = json.Unmarshal(m.Body, &msgBody); err != nil {
					t.Errorf("cannot unmarshall msg body into slice of notifications: %v", err)
				}
				rollup := tt.rollup
				if tt.rollup == 0 {
					rollup++
				}
				if len(msgBody) > rollup {
					t.Errorf("found more notes in msg than expected: rollup %d, got %d", rollup, len(msgBody))
				}
				conn.Ack(m)
			}

			// check if no msgs are left in the queue
			select {
			case <-sub.C:
				t.Fatal("there is still msg in subscription channel")
			case <-time.After(1 * time.Millisecond): // no msg found, as expected
			}
		})
	}
}
