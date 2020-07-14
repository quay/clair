package amqp

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/quay/clair/v4/notifier"
	"github.com/quay/claircore"
	"github.com/quay/claircore/test/integration"
	samqp "github.com/streadway/amqp"
	"golang.org/x/sync/errgroup"
)

// TestDirectDeliverer confirms delivery of notifications directly
// to the AMQP queue with rollup works correctly.
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

	uri := os.Getenv("RABBITMQ_CONNECTION_STRING")
	if uri == "" {
		uri = defaultRabbitMQURI
	}
	conn, err := samqp.Dial(uri)
	if err != nil {
		t.Fatalf("failed to connect to broker at %v: %v", uri, err)
	}
	// our test assumes a default exchange
	exchange := Exchange{
		Name:       "",
		Type:       "direct",
		Durable:    true,
		AutoDelete: false,
	}
	defer conn.Close()
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			// rabbitmq queue declare
			var (
				queueAndKey = tt.name + "-" + uuid.New().String()
			)
			ch, err := conn.Channel()
			if err != nil {
				t.Fatalf("failed to obtain channel from broker %v: %v", uri, err)
			}
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
			conf := Config{
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
					d, err := NewDirectDeliverer(conf)
					if err != nil {
						return fmt.Errorf("could not create deliverer: %v", err)
					}
					err = d.Notifications(context.TODO(), notes)
					if err != nil {
						return fmt.Errorf("failed to provide notifications to direct deliverer: %v", err)
					}
					// we simply need to check for an error. rabbitmq
					// will error if message cannot be delivered to broker
					err = d.Deliver(context.TODO(), noteID)
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
