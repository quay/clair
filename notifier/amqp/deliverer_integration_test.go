package amqp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/google/uuid"
	"github.com/quay/clair/config"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/zlog"
	amqp "github.com/rabbitmq/amqp091-go"
)

const (
	defaultRabbitMQURI = "amqp://guest:guest@localhost:5672/"
)

// TestDeliverer delivery confirms a notification
// callback is successfully delivered to the amqp broker.
func TestDeliverer(t *testing.T) {
	integration.Skip(t)
	ctx := zlog.Test(context.Background(), t)
	const (
		callback = "http://clair-notifier/notifier/api/v1/notification"
	)
	var (
		uri         = os.Getenv("RABBITMQ_CONNECTION_STRING")
		queueAndKey = uuid.New().String()
		// our test assumes a default exchange
		conf = config.AMQP{
			Callback: callback,
			Exchange: config.Exchange{
				Name:       "",
				Type:       "direct",
				Durable:    true,
				AutoDelete: false,
			},
			RoutingKey: queueAndKey,
		}
	)
	if uri == "" {
		uri = defaultRabbitMQURI
	}
	t.Logf("using uri: %q", uri)

	conf.URIs = []string{
		// give a few bogus URIs to confirm failover mechanisms are working
		"amqp://guest:guest@nohost1:5672/",
		"amqp://guest:guest@nohost2:5672/",
		"amqp://guest:guest@nohost3:5672/",
		uri,
	}

	conn, err := amqp.Dial(uri)
	if err != nil {
		t.Fatalf("failed to connect to broker at %v: %v", uri, err)
	}
	defer conn.Close()

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

	// test parallel usage
	g := errgroup.Group{}
	for i := 0; i < 4; i++ {
		g.Go(func() error {
			noteID := uuid.New()
			d, err := New(&conf)
			if err != nil {
				return fmt.Errorf("could not create deliverer: %v", err)
			}
			// we simply need to check for an error. amqp
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
	for i := 0; i < 4; i++ {
		m := <-msgs
		if m.ContentType != "application/json" {
			t.Errorf("msg content type mismatch: expected %s, got %s", "application/json", m.ContentType)
		}
		if m.AppId != "clairV4-notifier" {
			t.Errorf("msg app ID mismatch: expected %s, got %s", "clairV4-notifier", m.AppId)
		}
		var msgBody map[string]string
		if err = json.Unmarshal(m.Body, &msgBody); err != nil {
			t.Errorf("cannot unmarshall msg body into map: %v", err)
		}
		nid, ok := msgBody["notification_id"]
		if !ok {
			t.Errorf("cannot find \"notification_id\" key in msg body")
		}
		cb, ok := msgBody["callback"]
		if !ok {
			t.Errorf("cannot find \"callback\" key in msg body")
		}
		if cb != fmt.Sprintf("%s/%s", callback, nid) {
			t.Errorf("callback mismatch: expected: %s, got %s", fmt.Sprintf("%s/%s", callback, nid), cb)
		}
		m.Ack(false)
	}

	// check if msgs channel is empty
	select {
	case m := <-msgs:
		t.Fatalf("there is still msg in msgs channel: %#v", m)
	case <-time.After(1 * time.Millisecond): // no msg found, as expected
	}
}
