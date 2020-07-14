package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jmoiron/sqlx"
	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/matcher"
	"github.com/quay/clair/v4/notifier"
	namqp "github.com/quay/clair/v4/notifier/amqp"
	"github.com/quay/clair/v4/notifier/migrations"
	"github.com/quay/clair/v4/notifier/postgres"
	"github.com/quay/clair/v4/notifier/stomp"
	"github.com/quay/clair/v4/notifier/webhook"
	"github.com/quay/clair/v4/pkg/pager"
	pgdl "github.com/quay/claircore/pkg/distlock/postgres"
	"github.com/remind101/migrate"
	"github.com/rs/zerolog"
)

const (
	processors = 4
	deliveries = 4
)

// Service is an interface wrapping ClairV4's notifier functionality.
type Service interface {
	// Retrieves an optional paginated set of notifications given an notification id
	Notifications(ctx context.Context, id uuid.UUID, page *pager.Page) ([]notifier.Notification, pager.Page, error)
	// Deletes the provided notification id
	DeleteNotifications(ctx context.Context, id uuid.UUID) error
}

// service is a local implementation of a notifier service.
type service struct {
	store notifier.Store
}

func (s *service) Notifications(ctx context.Context, id uuid.UUID, page *pager.Page) ([]notifier.Notification, pager.Page, error) {
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
	Webhook          *webhook.Config
	AMQP             *namqp.Config
	STOMP            *stomp.Config
}

// New kicks off the notifier subsystem.
//
// Canceling the ctx will kill any concurrent routines affiliated with
// the notifier.
func New(ctx context.Context, opts Opts) (*service, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "notifier/service/Init").
		Logger()
	ctx = log.WithContext(ctx)

	// initialize store and dist lock pool
	store, lockPool, err := storeInit(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize store and lockpool: %v", err)
	}

	// kick off the poller
	log.Info().Str("interval", opts.PollInterval.String()).Msg("intializing poller")
	poller := notifier.NewPoller(opts.PollInterval, store, opts.Matcher)
	c := poller.Poll(ctx)

	// kick off the processors
	log.Info().Int("count", processors).Msg("intializing processors")
	for i := 0; i < processors; i++ {
		// processors only use try locks
		distLock := pgdl.NewLock(lockPool, 0)
		p := notifier.NewProcessor(
			i,
			distLock,
			opts.Indexer,
			opts.Matcher,
			store,
		)
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

func storeInit(ctx context.Context, opts Opts) (*postgres.Store, *sqlx.DB, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "notifier/service/storeInit").
		Logger()
	ctx = log.WithContext(ctx)

	cfg, err := pgxpool.ParseConfig(opts.ConnString)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse ConnString: %v", err)
	}
	cfg.MaxConns = 30
	pool, err := pgxpool.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create ConnPool: %v", err)
	}

	lockPool, err := sqlx.Connect("pgx", opts.ConnString)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create lock ConnPool: %v", err)
	}

	// do migrations if requested
	if opts.Migrations {
		log.Info().Msg("performing notifier migrations")
		migrator := migrate.NewPostgresMigrator(lockPool.DB)
		migrator.Table = migrations.MigrationTable
		err := migrator.Exec(migrate.Up, migrations.Migrations...)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to perform migrations: %w", err)
		}
	}

	log.Info().Msg("intializing notifier store")
	store := postgres.NewStore(pool)
	return store, lockPool, nil
}

func webhookDeliveries(ctx context.Context, opts Opts, lockPool *sqlx.DB, store notifier.Store) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "notifier/service/webhookInit").
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Int("count", deliveries).Msg("intializing webhook deliverers")

	conf, err := opts.Webhook.Validate()
	if err != nil {
		return err
	}

	ds := make([]*notifier.Delivery, 0, deliveries)
	for i := 0; i < deliveries; i++ {
		distLock := pgdl.NewLock(lockPool, 0)
		wh, err := webhook.New(conf, nil)
		if err != nil {
			return fmt.Errorf("failed to create webhook deliverer: %v", err)
		}
		delivery := notifier.NewDelivery(i, wh, opts.DeliveryInterval, store, distLock)
		ds = append(ds, delivery)
	}
	for _, d := range ds {
		d.Deliver(ctx)
	}
	return nil
}

func amqpDeliveries(ctx context.Context, opts Opts, lockPool *sqlx.DB, store notifier.Store) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "notifier/service/amqpInit").
		Logger()
	ctx = log.WithContext(ctx)

	conf, err := opts.AMQP.Validate()
	if err != nil {
		return fmt.Errorf("amqp validation failed: %v", err)
	}

	if len(conf.URIs) == 0 {
		log.Warn().Msg("amqp delivery was configured with no broker URIs to connect to. delivery of notifications will not occur.")
		return nil
	}

	// fo := &namqp.FailOver{
	// 	Config: conf,
	// }

	ds := make([]*notifier.Delivery, 0, deliveries)
	for i := 0; i < deliveries; i++ {
		distLock := pgdl.NewLock(lockPool, 0)
		if conf.Direct {
			q, err := namqp.NewDirectDeliverer(conf)
			if err != nil {
				return fmt.Errorf("failed to create AMQP deliverer: %v", err)
			}
			delivery := notifier.NewDelivery(i, q, opts.DeliveryInterval, store, distLock)
			ds = append(ds, delivery)
		} else {
			q, err := namqp.New(conf)
			if err != nil {
				return fmt.Errorf("failed to create AMQP deliverer: %v", err)
			}
			delivery := notifier.NewDelivery(i, q, opts.DeliveryInterval, store, distLock)
			ds = append(ds, delivery)
		}
	}
	for _, d := range ds {
		d.Deliver(ctx)
	}

	return nil
}

func stompDeliveries(ctx context.Context, opts Opts, lockPool *sqlx.DB, store notifier.Store) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "notifier/service/stompInit").
		Logger()
	ctx = log.WithContext(ctx)

	conf, err := opts.STOMP.Validate()
	if err != nil {
		return fmt.Errorf("stomp validation failed: %v", err)
	}

	if len(conf.URIs) == 0 {
		log.Warn().Msg("stomp delivery was configured with no broker URIs to connect to. delivery of notifications will not occur.")
		return nil
	}

	// fo := &stomp.FailOver{
	// 	Config: conf,
	// }

	ds := make([]*notifier.Delivery, 0, deliveries)
	for i := 0; i < deliveries; i++ {
		distLock := pgdl.NewLock(lockPool, 0)
		if conf.Direct {
			q, err := stomp.NewDirectDeliverer(conf)
			if err != nil {
				return fmt.Errorf("failed to create STOMP direct deliverer: %v", err)
			}
			delivery := notifier.NewDelivery(i, q, opts.DeliveryInterval, store, distLock)
			ds = append(ds, delivery)
		} else {
			q, err := stomp.New(conf)
			if err != nil {
				return fmt.Errorf("failed to create STOMP deliverer: %v", err)
			}
			delivery := notifier.NewDelivery(i, q, opts.DeliveryInterval, store, distLock)
			ds = append(ds, delivery)
		}
	}
	for _, d := range ds {
		d.Deliver(ctx)
	}

	return nil
}
