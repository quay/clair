package stomp

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/claircore/test/log"
	"golang.org/x/sync/errgroup"
)

const (
	defaultStompBrokerURI = "localhost:61613"
)

// TestDeliverer confirms a notification
// callback is successfully delivered to the stomp broker.
func TestDeliverer(t *testing.T) {
	integration.Skip(t)
	ctx := log.TestLogger(context.Background(), t)
	const (
		callback = "http://clair-notifier/api/v1/notifications"
	)

	var (
		uri  = os.Getenv("STOMP_CONNECTION_STRING")
		conf = Config{
			Callback:    callback,
			Destination: "notifications",
			Direct:      false,
		}
	)
	if uri == "" {
		uri = defaultStompBrokerURI
	}
	conf.URIs = []string{
		// give a few bogus URIs to confirm failover mechanisms are working
		"nohost1:5672/",
		"nohost2:5672/",
		"nohost3:5672/",
		uri,
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
}
