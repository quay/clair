package amqp

import (
	"context"
	"fmt"
	"os"
	"testing"

	"golang.org/x/sync/errgroup"

	"github.com/google/uuid"
	"github.com/quay/claircore/test/integration"
	samqp "github.com/streadway/amqp"
)

const (
	defaultRabbitMQURI = "amqp://guest:guest@localhost:5672/"
)

// TestDeliverer delivery confirms a notification
// callback is successfully delivered to the amqp broker.
func TestDeliverer(t *testing.T) {
	integration.Skip(t)
	const (
		callback = "http://clair-notifier/api/v1/notifications"
	)
	var (
		uri         = os.Getenv("RABBITMQ_CONNECTION_STRING")
		queueAndKey = uuid.New().String()
		// our test assumes a default exchange
		exchange = Exchange{
			Name:       "",
			Type:       "direct",
			Durable:    true,
			AutoDelete: false,
		}
		conf = Config{
			Callback:   callback,
			Exchange:   exchange,
			RoutingKey: queueAndKey,
		}
	)
	if uri == "" {
		uri = defaultRabbitMQURI
	}

	conf.URIs = []string{
		// give a few bogus URIs to confirm failover mechanisms are working
		"amqp://guest:guest@nohost1:5672/",
		"amqp://guest:guest@nohost2:5672/",
		"amqp://guest:guest@nohost3:5672/",
		uri,
	}

	conn, err := samqp.Dial(uri)
	if err != nil {
		t.Fatalf("failed to connect to broker at %v: %v", uri, err)
	}
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

	// test parallel usage
	g := errgroup.Group{}
	for i := 0; i < 4; i++ {
		g.Go(func() error {
			noteID := uuid.New()
			d, err := New(conf)
			if err != nil {
				return fmt.Errorf("could not create deliverer: %v", err)
			}
			// we simply need to check for an error. amqp
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

}
