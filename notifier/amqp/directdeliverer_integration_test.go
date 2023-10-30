package amqp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/quay/clair/config"
	"github.com/quay/claircore"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/zlog"
	amqp "github.com/rabbitmq/amqp091-go"
	"golang.org/x/sync/errgroup"

	"github.com/quay/clair/v4/notifier"
)

// TestDirectDeliverer confirms delivery of notifications directly
// to the AMQP queue with rollup works correctly.
func TestDirectDeliverer(t *testing.T) {
	integration.Skip(t)
	ctx := zlog.Test(context.Background(), t)
	// test start
	table := []struct {
		name         string
		rollup       int
		notes        int
		expectedMsgs int
	}{
		{
			name:         "0",
			rollup:       0,
			notes:        1,
			expectedMsgs: 1,
		},
		{
			name:         "1",
			rollup:       1,
			notes:        5,
			expectedMsgs: 5,
		},
		{
			name:         "RollupOverflow",
			rollup:       10,
			notes:        5,
			expectedMsgs: 1,
		},
		{
			name:         "Odds",
			rollup:       3,
			notes:        7,
			expectedMsgs: 3,
		},
		{
			name:         "OddsRollup",
			rollup:       3,
			notes:        8,
			expectedMsgs: 3,
		},
		{
			name:         "OddsNotes",
			rollup:       4,
			notes:        7,
			expectedMsgs: 2,
		},
		{
			name:         "Large",
			rollup:       100,
			notes:        1000,
			expectedMsgs: 10,
		},
	}

	uri := os.Getenv("RABBITMQ_CONNECTION_STRING")
	if uri == "" {
		uri = defaultRabbitMQURI
	}
	t.Logf("using uri: %q", uri)
	conn, err := amqp.Dial(uri)
	if err != nil {
		t.Fatalf("failed to connect to broker at %v: %v", uri, err)
	}
	defer conn.Close()
	// our test assumes a default exchange
	exchange := config.Exchange{
		Name:       "",
		Type:       "direct",
		Durable:    true,
		AutoDelete: false,
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			// rabbitmq queue declare

			queueAndKey := tt.name + "-" + uuid.New().String()

			ch, err := conn.Channel()
			if err != nil {
				t.Fatalf("failed to obtain channel from broker %v: %v", uri, err)
			}
			defer ch.Close()
			// this queue will autobind to the default "direct" exchange
			// and the queue name may be used as the routing key.
			_, err = ch.QueueDeclare(
				queueAndKey,
				true,
				false,
				false,
				false,
				nil,
			)
			if err != nil {
				t.Fatalf("failed to declare queue: %v", err)
			}

			// deliverer test
			conf := config.AMQP{
				Direct: true,
				Rollup: tt.rollup,
				// values come from rabbitmq setup
				RoutingKey: queueAndKey,
				Exchange:   exchange,
				URIs: []string{
					// give a few bogus URIs to confirm failover mechanisms are working
					"amqp://guest:guest@nohost1:5672/",
					"amqp://guest:guest@nohost2:5672/",
					"amqp://guest:guest@nohost3:5672/",
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
					// we simply need to check for an error. rabbitmq
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
			consumerConn, err := amqp.Dial(uri)
			if err != nil {
				t.Fatalf("failed to create consumer connection: %v", err)
			}
			defer consumerConn.Close()

			consumerCh, err := consumerConn.Channel()
			if err != nil {
				t.Fatalf("failed to create consumer channel: %v", err)
			}
			defer consumerCh.Close()

			msgs, err := consumerCh.Consume(
				queueAndKey,
				"test",
				false,
				false,
				false,
				false,
				nil,
			)
			if err != nil {
				t.Fatalf("failed to start consuming messages: %v", err)
			}

			// read messages
			totalExpectedMsgs := tt.expectedMsgs * 4
			for i := 0; i < totalExpectedMsgs; i++ {
				m := <-msgs
				if m.ContentType != "application/json" {
					t.Errorf("msg content type mismatch: expected %s, got %s", "application/json", m.ContentType)
				}
				if m.AppId != "clairV4-notifier" {
					t.Errorf("msg app ID mismatch: expected %s, got %s", "clairV4-notifier", m.AppId)
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
					t.Errorf("found more notifications in msg than expected: rollup %d, got %d", rollup, len(msgBody))
				}
				m.Ack(false)
			}

			// check if msgs channel is empty
			select {
			case <-msgs:
				t.Fatal("there is still msg in msgs channel")
			case <-time.After(1 * time.Millisecond): // no msg found, as expected
			}
		})
	}
}
