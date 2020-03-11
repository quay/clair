package initialize

import (
	"fmt"
	"time"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/config"
	"github.com/quay/clair/v4/httptransport/client"
	"github.com/quay/claircore/libindex"
	"github.com/quay/claircore/libvuln"
	"github.com/rs/zerolog"
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
		})
		if err != nil {
			return fmt.Errorf("failed to initialize libvuln: %v", err)
		}
		i.Indexer = libI
		i.Matcher = libV
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
		})
		if err != nil {
			return fmt.Errorf("failed to initialize libvuln: %v", err)
		}
		// matcher mode needs a remote indexer client
		remoteIndexer, err := client.NewHTTPClient(i.GlobalCTX, i.conf, nil)
		if err != nil {
			return err
		}
		i.Indexer = remoteIndexer
		i.Matcher = libV
	default:
		return fmt.Errorf("could not determine passed in mode: %v", i.conf.Mode)
	}

	return nil
}
