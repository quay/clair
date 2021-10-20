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
	"github.com/quay/clair/config"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/zlog"
	"golang.org/x/sync/errgroup"
)

const (
	defaultStompBrokerURI = "localhost:61613"
)

// TestDeliverer confirms a notification
// callback is successfully delivered to the stomp broker.
func TestDeliverer(t *testing.T) {
	integration.Skip(t)
	ctx := zlog.Test(context.Background(), t)
	const (
		callback = "http://clair-notifier/notifier/api/v1/notifications/"
	)

	var (
		uri   = os.Getenv("STOMP_CONNECTION_STRING")
		queue = uuid.New().String()
		conf  = config.STOMP{
			Callback:    callback,
			Destination: queue,
			Direct:      false,
		}
	)
	if uri == "" {
		uri = defaultStompBrokerURI
	}
	conf.URIs = []string{
		// give a few bogus URIs to confirm failover mechanisms are working
		"nohost1:5672",
		"nohost2:5672",
		"nohost3:5672",
		uri,
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
	for i := 0; i < 4; i++ {
		m, err := sub.Read()
		if err != nil {
			t.Fatalf("cannot read msg from subscription: %v", err)
		}
		if m.ContentType != "application/json" {
			t.Errorf("msg content type mismatch: expected %s, got %s", "application/json", m.ContentType)
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
		if got, want := cb, callback+nid; got != want {
			t.Errorf("callback mismatch: got: %q, want: %q", got, want)
		}
		conn.Ack(m)
	}

	// check if no msgs are left in the queue
	select {
	case m := <-sub.C:
		t.Fatalf("there is still msg in subscription channel: %#v", m)
	case <-time.After(1 * time.Millisecond): // no msg found, as expected
	}
}
