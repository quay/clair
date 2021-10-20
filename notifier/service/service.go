package service

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	_ "github.com/jackc/pgx/v4/stdlib"
	"github.com/quay/clair/config"
	"github.com/quay/claircore/pkg/ctxlock"
	"github.com/quay/zlog"
	"github.com/remind101/migrate"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/matcher"
	"github.com/quay/clair/v4/notifier"
	namqp "github.com/quay/clair/v4/notifier/amqp"
	"github.com/quay/clair/v4/notifier/migrations"
	"github.com/quay/clair/v4/notifier/postgres"
	"github.com/quay/clair/v4/notifier/stomp"
	"github.com/quay/clair/v4/notifier/webhook"
)

const (
	processors = 4
	deliveries = 4
)

// Service is an interface wrapping ClairV4's notifier functionality.
//
// This remains an interface so remote clients may implement as well.
type Service interface {
	// Retrieves an optional paginated set of notifications given an notification id
	Notifications(ctx context.Context, id uuid.UUID, page *notifier.Page) ([]notifier.Notification, notifier.Page, error)
	// Deletes the provided notification id
	DeleteNotifications(ctx context.Context, id uuid.UUID) error
}

var _ Service = (*service)(nil)

// service is a local implementation of a notifier service.
type service struct {
	store notifier.Store
}

func (s *service) Notifications(ctx context.Context, id uuid.UUID, page *notifier.Page) ([]notifier.Notification, notifier.Page, error) {
	return s.store.Notifications(ctx, id, page)
}

func (s *service) DeleteNotifications(ctx context.Context, id uuid.UUID) error {
	return s.store.SetDeleted(ctx, id)
}

// Opts configures the notifier service
type Opts struct {
	PollInterval     time.Duration
	DeliveryInterval time.Duration
	Migrations       bool
	ConnString       string
	Matcher          matcher.Service
	Indexer          indexer.Service
	DisableSummary   bool
	Client           *http.Client
	Webhook          *config.Webhook
	AMQP             *config.AMQP
	STOMP            *config.STOMP
}

// New kicks off the notifier subsystem.
//
// Canceling the ctx will kill any concurrent routines affiliated with
// the notifier.
func New(ctx context.Context, opts Opts) (*service, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "notifier/service/New"),
	)

	// initialize store and dist lock pool
	store, lockPool, err := storeInit(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize store and lockpool: %v", err)
	}

	// check for test mode
	if tm := os.Getenv("NOTIFIER_TEST_MODE"); tm != "" {
		zlog.Warn(ctx).
			Stringer("interval", opts.PollInterval).
			Msg("NOTIFIER TEST MODE ENABLED. NOTIFIER WILL CREATE TEST NOTIFICATIONS ON A SET INTERVAL")
		testModeInit(ctx, &opts)
	}

	// kick off the poller
	zlog.Info(ctx).
		Stringer("interval", opts.PollInterval).
		Msg("initializing poller")
	poller := notifier.NewPoller(opts.PollInterval, store, opts.Matcher)
	c := poller.Poll(ctx)

	// kick off the processors
	zlog.Info(ctx).
		Int("count", processors).
		Msg("initializing processors")
	for i := 0; i < processors; i++ {
		// Can't re-use a locker because the Process method unconditionally
		// spawns background goroutines.
		l, err := ctxlock.New(ctx, lockPool)
		if err != nil {
			return nil, err
		}
		p := notifier.NewProcessor(
			i,
			l,
			opts.Indexer,
			opts.Matcher,
			store,
		)
		p.NoSummary = opts.DisableSummary
		p.Process(ctx, c)
	}

	// kick off configured deliverer type
	switch {
	case opts.Webhook != nil:
		if err := webhookDeliveries(ctx, opts, lockPool, store); err != nil {
			return nil, err
		}
	case opts.AMQP != nil:
		if err := amqpDeliveries(ctx, opts, lockPool, store); err != nil {
			return nil, err
		}
	case opts.STOMP != nil:
		if err := stompDeliveries(ctx, opts, lockPool, store); err != nil {
			return nil, err
		}
	}

	return &service{
		store: store,
	}, nil
}

// testModeInit will inject a mock Indexer and Matcher into opts
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

func storeInit(ctx context.Context, opts Opts) (*postgres.Store, *pgxpool.Pool, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "notifier/service/storeInit"),
	)

	cfg, err := pgxpool.ParseConfig(opts.ConnString)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse ConnString: %v", err)
	}
	cfg.MaxConns = 30
	pool, err := pgxpool.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create ConnPool: %v", err)
	}

	db, err := sql.Open("pgx", opts.ConnString)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open db: %v", err)
	}
	defer db.Close()

	// do migrations if requested
	if opts.Migrations {
		zlog.Info(ctx).Msg("performing notifier migrations")
		migrator := migrate.NewPostgresMigrator(db)
		migrator.Table = migrations.MigrationTable
		err := migrator.Exec(migrate.Up, migrations.Migrations...)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to perform migrations: %w", err)
		}
	}

	zlog.Info(ctx).Msg("initializing notifier store")
	store := postgres.NewStore(pool)
	return store, pool, nil
}

func webhookDeliveries(ctx context.Context, opts Opts, lockPool *pgxpool.Pool, store notifier.Store) error {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "notifier/service/webhookDeliveries"),
	)
	zlog.Info(ctx).
		Int("count", deliveries).
		Msg("initializing webhook deliverers")

	ds := make([]*notifier.Delivery, 0, deliveries)
	for i := 0; i < deliveries; i++ {
		// Can't share a ctxlock because the Deliverer object unconditionally
		// spawns background goroutines.
		l, err := ctxlock.New(ctx, lockPool)
		if err != nil {
			return fmt.Errorf("failed to create locker: %w", err)
		}
		wh, err := webhook.New(opts.Webhook, opts.Client)
		if err != nil {
			return fmt.Errorf("failed to create webhook deliverer: %v", err)
		}
		delivery := notifier.NewDelivery(i, wh, opts.DeliveryInterval, store, l)
		ds = append(ds, delivery)
	}
	for _, d := range ds {
		d.Deliver(ctx)
	}
	return nil
}

func amqpDeliveries(ctx context.Context, opts Opts, lockPool *pgxpool.Pool, store notifier.Store) error {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "notifier/service/amqpDeliveries"),
	)

	conf := opts.AMQP
	if len(conf.URIs) == 0 {
		zlog.Warn(ctx).
			Msg("amqp delivery was configured with no broker URIs to connect to. delivery of notifications will not occur.")
		return nil
	}

	ds := make([]*notifier.Delivery, 0, deliveries)
	for i := 0; i < deliveries; i++ {
		// Can't share a ctxlock because the Deliverer object unconditionally
		// spawns background goroutines.
		l, err := ctxlock.New(ctx, lockPool)
		if err != nil {
			return fmt.Errorf("failed to create locker: %w", err)
		}
		if conf.Direct {
			q, err := namqp.NewDirectDeliverer(conf)
			if err != nil {
				return fmt.Errorf("failed to create AMQP deliverer: %v", err)
			}
			delivery := notifier.NewDelivery(i, q, opts.DeliveryInterval, store, l)
			ds = append(ds, delivery)
		} else {
			q, err := namqp.New(conf)
			if err != nil {
				return fmt.Errorf("failed to create AMQP deliverer: %v", err)
			}
			delivery := notifier.NewDelivery(i, q, opts.DeliveryInterval, store, l)
			ds = append(ds, delivery)
		}
	}
	for _, d := range ds {
		d.Deliver(ctx)
	}

	return nil
}

func stompDeliveries(ctx context.Context, opts Opts, lockPool *pgxpool.Pool, store notifier.Store) error {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "notifier/service/stompDeliveries"),
	)

	conf := opts.STOMP
	if len(conf.URIs) == 0 {
		zlog.Warn(ctx).
			Msg("stomp delivery was configured with no broker URIs to connect to. delivery of notifications will not occur.")
		return nil
	}

	ds := make([]*notifier.Delivery, 0, deliveries)
	for i := 0; i < deliveries; i++ {
		// Can't share a ctxlock because the Deliverer object unconditionally
		// spawns background goroutines.
		l, err := ctxlock.New(ctx, lockPool)
		if err != nil {
			return fmt.Errorf("failed to create locker: %w", err)
		}
		if conf.Direct {
			q, err := stomp.NewDirectDeliverer(conf)
			if err != nil {
				return fmt.Errorf("failed to create STOMP direct deliverer: %v", err)
			}
			delivery := notifier.NewDelivery(i, q, opts.DeliveryInterval, store, l)
			ds = append(ds, delivery)
		} else {
			q, err := stomp.New(conf)
			if err != nil {
				return fmt.Errorf("failed to create STOMP deliverer: %v", err)
			}
			delivery := notifier.NewDelivery(i, q, opts.DeliveryInterval, store, l)
			ds = append(ds, delivery)
		}
	}
	for _, d := range ds {
		d.Deliver(ctx)
	}

	return nil
}
