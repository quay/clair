package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/google/uuid"
	"github.com/quay/clair/config"
	"github.com/quay/zlog"
	"golang.org/x/sync/errgroup"

	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/matcher"
	"github.com/quay/clair/v4/notifier"
	"github.com/quay/clair/v4/notifier/amqp"
	"github.com/quay/clair/v4/notifier/stomp"
	"github.com/quay/clair/v4/notifier/webhook"
)

var (
	processors = runtime.GOMAXPROCS(0)
	deliveries = runtime.GOMAXPROCS(0)
)

var _ notifier.Service = (*Notifier)(nil)

// ErrNoDelivery is returned when there's insufficient configuration for
// notification delivery.
var ErrNoDelivery = errors.New("no delivery mechanisms configured")

// Notifier is a local implementation of a notifier service.
type Notifier struct {
	store notifier.Store
	poll  *notifier.Poller
	proc  *notifier.Processor
	del   *notifier.Delivery
}

// Notifications implements notifier.Service.
func (s *Notifier) Notifications(ctx context.Context, id uuid.UUID, page *notifier.Page) ([]notifier.Notification, notifier.Page, error) {
	return s.store.Notifications(ctx, id, page)
}

// DeleteNotifications implements notifier.Service.
func (s *Notifier) DeleteNotifications(ctx context.Context, id uuid.UUID) error {
	return s.store.SetDeleted(ctx, id)
}

// Opts configures the notifier service.
type Opts struct {
	Matcher          matcher.Service
	Indexer          indexer.Service
	Signer           webhook.Signer
	Client           *http.Client
	Webhook          *config.Webhook
	AMQP             *config.AMQP
	STOMP            *config.STOMP
	PollInterval     time.Duration
	DeliveryInterval time.Duration
	DisableSummary   bool
}

// New returns a configured notifier subsystem.
func New(ctx context.Context, store notifier.Store, locks notifier.Locker, opts Opts) (*Notifier, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "notifier/service/New")
	srv := Notifier{store: store}

	// Check for test mode.
	if tm := os.Getenv("NOTIFIER_TEST_MODE"); tm != "" {
		zlog.Warn(ctx).
			Stringer("interval", opts.PollInterval).
			Msg("NOTIFIER TEST MODE ENABLED. NOTIFIER WILL CREATE TEST NOTIFICATIONS ON A SET INTERVAL")
		testModeInit(ctx, &opts)
	}

	// Configure the Poller.
	zlog.Info(ctx).
		Stringer("interval", opts.PollInterval).
		Msg("initializing poller")
	srv.poll = notifier.NewPoller(store, opts.Matcher, opts.PollInterval)

	// Configure the Processor.
	zlog.Info(ctx).
		Int("count", processors).
		Msg("initializing processors")
	srv.proc = notifier.NewProcessor(store, locks, opts.Indexer, opts.Matcher)
	srv.proc.NoSummary = opts.DisableSummary

	// Configure a Deliverer.
	var del notifier.Deliverer
	var err error
	// BUG(hank) Currently only one delivery mechanism can be configured at a
	// time.
	switch {
	case opts.Webhook != nil:
		zlog.Info(ctx).
			Int("count", deliveries).
			Msg("initializing webhook deliverers")
		del, err = webhook.New(opts.Webhook, opts.Client, opts.Signer)
		if err != nil {
			return nil, fmt.Errorf("failed to create webhook deliverer: %v", err)
		}
	case opts.AMQP != nil:
		conf := opts.AMQP
		if len(conf.URIs) == 0 {
			zlog.Warn(ctx).
				Msg("amqp delivery misconfigured: no broker URIs to connect to")
			break
		}
		if conf.Direct {
			del, err = amqp.NewDirectDeliverer(conf)
			if err != nil {
				return nil, fmt.Errorf("failed to create AMQP deliverer: %v", err)
			}
			break
		}
		del, err = amqp.New(conf)
		if err != nil {
			return nil, fmt.Errorf("failed to create AMQP deliverer: %v", err)
		}
	case opts.STOMP != nil:
		conf := opts.STOMP
		if len(conf.URIs) == 0 {
			zlog.Warn(ctx).
				Msg("stomp delivery misconfigured: no broker URIs to connect to")
			break
		}
		if conf.Direct {
			del, err = stomp.NewDirectDeliverer(conf)
			if err != nil {
				return nil, fmt.Errorf("failed to create STOMP direct deliverer: %v", err)
			}
			break
		}
		del, err = stomp.New(conf)
		if err != nil {
			return nil, fmt.Errorf("failed to create STOMP deliverer: %v", err)
		}
	}
	if del == nil {
		// Report an error if configured such that no notifications are being
		// processed.
		return nil, ErrNoDelivery
	}
	srv.del = notifier.NewDelivery(store, locks, del, opts.DeliveryInterval)

	return &srv, nil
}

// TestModeInit will inject a mock Indexer and Matcher into opts
// to be used in testing mode.
func testModeInit(ctx context.Context, opts *Opts) error {
	mm := &matcher.Mock{}
	im := &indexer.Mock{}
	matcherForTestMode(mm)
	indexerForTestMode(im)
	opts.Matcher = mm
	opts.Indexer = im
	return nil
}

// Run spawns all needed background goroutines and waits for the first error.
//
// Canceling the supplied Context should return context.Canceled.
func (s *Notifier) Run(ctx context.Context) error {
	ctx = zlog.ContextWithValues(ctx, "component", "notifier/service/Notifier.Run")
	// Channel for poller to processor communication.
	ch := make(chan notifier.Event, notifier.MaxChanSize)
	eg, ctx := errgroup.WithContext(ctx)
	// Poller goroutine.
	eg.Go(func() error { return s.poll.Poll(ctx, ch) })
	// Processor goroutines.
	for i := 0; i < processors; i++ {
		eg.Go(func() error { return s.proc.Process(ctx, ch) })
	}
	// Garbage collection goroutine.
	eg.Go(s.gc(ctx))
	// Delivery goroutines.
	for i := 0; i < deliveries; i++ {
		eg.Go(func() error { return s.del.Deliver(ctx) })
	}
	return eg.Wait()
}

// Gc is the garbage collection process.
func (s *Notifier) gc(ctx context.Context) func() error {
	// BUG(hank) The garbage collection period is currently unconfigurable.
	ctx = zlog.ContextWithValues(ctx, "component", "notifier/service/Notifier.gc")
	ticker := time.NewTicker(time.Hour)
	return func() error {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
				if err := s.store.CollectNotifications(ctx); err != nil {
					zlog.Info(ctx).Err(err).Msg("gc errored")
				}
				zlog.Info(ctx).Msg("gc done")
			}
		}
	}
}
