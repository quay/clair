package initialize

import (
	"fmt"
	"time"

	notifier "github.com/quay/clair/v4/notifier/service"
	"github.com/quay/claircore/libindex"
	"github.com/quay/claircore/libvuln"
	"github.com/rs/zerolog"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/config"
	"github.com/quay/clair/v4/httptransport/client"
)

// Services will initialize the correct ClairCore services
// dependent on operation mode.
//
// Services maybe local or remote (over a network).
func (i *Init) Services() error {
	log := zerolog.Ctx(i.GlobalCTX).With().Str("component", "init/Init.Services").Logger()
	log.Info().Msg("begin service initialization")

	switch i.conf.Mode {
	case config.ComboMode:
		// configure two local services via claircore libraries
		libI, err := libindex.New(i.GlobalCTX, &libindex.Opts{
			ConnString:           i.conf.Indexer.ConnString,
			ScanLockRetry:        time.Duration(i.conf.Indexer.ScanLockRetry) * time.Second,
			LayerScanConcurrency: i.conf.Indexer.LayerScanConcurrency,
			Migrations:           i.conf.Indexer.Migrations,
		})
		if err != nil {
			return clairerror.ErrNotInitialized{"failed to initialize libindex: " + err.Error()}
		}
		libV, err := libvuln.New(i.GlobalCTX, &libvuln.Opts{
			MaxConnPool: int32(i.conf.Matcher.MaxConnPool),
			ConnString:  i.conf.Matcher.ConnString,
			Migrations:  i.conf.Matcher.Migrations,
			UpdaterSets: i.conf.Matcher.UpdaterSets,
		})
		if err != nil {
			return fmt.Errorf("failed to initialize libvuln: %v", err)
		}

		// configure notifier service
		dInterval, err := time.ParseDuration(i.conf.Notifier.DeliveryInterval)
		if err != nil {
			return &clairerror.ErrNotInitialized{
				Msg: "notifier: failed to parse delivery interval: " + err.Error(),
			}
		}
		pInterval, err := time.ParseDuration(i.conf.Notifier.PollInterval)
		if err != nil {
			return &clairerror.ErrNotInitialized{
				Msg: "notifier: failed to parse poll interval: " + err.Error(),
			}
		}

		n, err := notifier.New(i.GlobalCTX, notifier.Opts{
			DeliveryInterval: dInterval,
			ConnString:       i.conf.Notifier.ConnString,
			Indexer:          libI,
			Matcher:          libV,
			Migrations:       i.conf.Notifier.Migrations,
			PollInterval:     pInterval,
			Webhook:          i.conf.Notifier.Webbook,
			AMQP:             i.conf.Notifier.AMQP,
			STOMP:            i.conf.Notifier.STOMP,
		})
		if err != nil {
			return &clairerror.ErrNotInitialized{
				Msg: "notifier failed to initialize: " + err.Error(),
			}
		}

		i.Indexer = libI
		i.Matcher = libV
		i.Notifier = n
	case config.IndexerMode:
		// configure just a local indexer
		libI, err := libindex.New(i.GlobalCTX, &libindex.Opts{
			ConnString:           i.conf.Indexer.ConnString,
			ScanLockRetry:        time.Duration(i.conf.Indexer.ScanLockRetry) * time.Second,
			LayerScanConcurrency: i.conf.Indexer.LayerScanConcurrency,
			Migrations:           i.conf.Indexer.Migrations,
		})
		if err != nil {
			return clairerror.ErrNotInitialized{"failed to initialize libindex: " + err.Error()}
		}
		i.Indexer = libI
		i.Matcher = nil
	case config.MatcherMode:
		// configure a local matcher but a remote indexer
		libV, err := libvuln.New(i.GlobalCTX, &libvuln.Opts{
			MaxConnPool: int32(i.conf.Matcher.MaxConnPool),
			ConnString:  i.conf.Matcher.ConnString,
			Migrations:  i.conf.Matcher.Migrations,
			UpdaterSets: i.conf.Matcher.UpdaterSets,
		})
		if err != nil {
			return fmt.Errorf("failed to initialize libvuln: %v", err)
		}
		// matcher mode needs a remote indexer client
		c, auth, err := i.conf.Client(nil)
		switch {
		case err != nil:
			return err
		case !auth && i.conf.Auth.Any():
			return &clairerror.ErrNotInitialized{
				Msg: "client authorization required but not provided",
			}
		default: // OK
		}
		remoteIndexer, err := client.NewHTTP(i.GlobalCTX,
			client.WithAddr(i.conf.Matcher.IndexerAddr),
			client.WithClient(c))
		if err != nil {
			return err
		}
		i.Indexer = remoteIndexer
		i.Matcher = libV
	case config.NotifierMode:
		// notifier uses a remote indexer and matcher
		c, auth, err := i.conf.Client(nil)
		switch {
		case err != nil:
			return err
		case !auth && i.conf.Auth.Any():
			return &clairerror.ErrNotInitialized{
				Msg: "client authorization required but not provided",
			}
		default: // OK
		}

		remoteIndexer, err := client.NewHTTP(i.GlobalCTX,
			client.WithAddr(i.conf.Notifier.IndexerAddr),
			client.WithClient(c))
		if err != nil {
			return err
		}

		remoteMatcher, err := client.NewHTTP(i.GlobalCTX,
			client.WithAddr(i.conf.Notifier.MatcherAddr),
			client.WithClient(c))
		if err != nil {
			return err
		}

		dInterval, err := time.ParseDuration(i.conf.Notifier.DeliveryInterval)
		if err != nil {
			return &clairerror.ErrNotInitialized{
				Msg: "notifier: failed to parse delivery interval: " + err.Error(),
			}
		}
		pInterval, err := time.ParseDuration(i.conf.Notifier.PollInterval)
		if err != nil {
			return &clairerror.ErrNotInitialized{
				Msg: "notifier: failed to parse poll interval: " + err.Error(),
			}
		}

		n, err := notifier.New(i.GlobalCTX, notifier.Opts{
			DeliveryInterval: dInterval,
			ConnString:       i.conf.Notifier.ConnString,
			Indexer:          remoteIndexer,
			Matcher:          remoteMatcher,
			Migrations:       i.conf.Notifier.Migrations,
			PollInterval:     pInterval,
			Webhook:          i.conf.Notifier.Webbook,
			AMQP:             i.conf.Notifier.AMQP,
			STOMP:            i.conf.Notifier.STOMP,
		})
		if err != nil {
			return &clairerror.ErrNotInitialized{
				Msg: "notifier failed to initialize: " + err.Error(),
			}
		}
		i.Indexer = remoteIndexer
		i.Matcher = remoteMatcher
		i.Notifier = n

	default:
		return fmt.Errorf("could not determine passed in mode: %v", i.conf.Mode)
	}

	return nil
}
