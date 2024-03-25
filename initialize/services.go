package initialize

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/clair/config"
	"github.com/quay/claircore/datastore/postgres"
	"github.com/quay/claircore/enricher/cvss"
	"github.com/quay/claircore/libindex"
	"github.com/quay/claircore/libvuln"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/ctxlock"
	"github.com/quay/zlog"
	"golang.org/x/net/publicsuffix"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/httptransport"
	"github.com/quay/clair/v4/httptransport/client"
	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/internal/httputil"
	"github.com/quay/clair/v4/matcher"
	"github.com/quay/clair/v4/notifier"
	notifierpg "github.com/quay/clair/v4/notifier/postgres"
	"github.com/quay/clair/v4/notifier/service"
)

const (
	// NotifierIssuer is the value used for the issuer claim of any outgoing
	// HTTP requests the notifier makes, if PSK auth is configured.
	NotifierIssuer = `clair-notifier`
)

var (
	intraserviceClaim = jwt.Claims{Issuer: httptransport.IntraserviceIssuer}
	notifierClaim     = jwt.Claims{Issuer: NotifierIssuer}
)

// Srv is a bundle of configured Services.
//
// The members are populated according to the configuration that was passed to
// Services.
type Srv struct {
	Indexer  indexer.Service
	Matcher  matcher.Service
	Notifier notifier.Service
}

// Services configures the services needed for a given mode according to the
// provided configuration.
func Services(ctx context.Context, cfg *config.Config) (*Srv, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "initialize/Services")
	zlog.Info(ctx).Msg("begin service initialization")
	defer zlog.Info(ctx).Msg("end service initialization")

	var srv Srv
	var err error
	switch cfg.Mode {
	case config.ComboMode:
		srv.Indexer, err = localIndexer(ctx, cfg)
		if err != nil {
			return nil, err
		}
		srv.Matcher, err = localMatcher(ctx, cfg)
		if err != nil {
			return nil, err
		}
		srv.Notifier, err = localNotifier(ctx, cfg, srv.Indexer, srv.Matcher)
		if err != nil {
			return nil, err
		}
	case config.IndexerMode:
		srv.Indexer, err = localIndexer(ctx, cfg)
		if err != nil {
			return nil, err
		}
	case config.MatcherMode:
		srv.Matcher, err = localMatcher(ctx, cfg)
		if err != nil {
			return nil, err
		}
		srv.Indexer, err = remoteIndexer(ctx, cfg, cfg.Matcher.IndexerAddr)
		if err != nil {
			return nil, err
		}
	case config.NotifierMode:
		srv.Indexer, err = remoteIndexer(ctx, cfg, cfg.Notifier.IndexerAddr)
		if err != nil {
			return nil, err
		}
		srv.Matcher, err = remoteMatcher(ctx, cfg, cfg.Notifier.MatcherAddr)
		if err != nil {
			return nil, err
		}
		srv.Notifier, err = localNotifier(ctx, cfg, srv.Indexer, srv.Matcher)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("could not determine passed in mode: %v", cfg.Mode)
	}

	return &srv, nil
}

// BUG(hank) The various resources (database connections, lock services)
// constructed in some internal functions are not properly cleaned up.

func localIndexer(ctx context.Context, cfg *config.Config) (indexer.Service, error) {
	const msg = "failed to initialize indexer: "
	mkErr := func(err error) *clairerror.ErrNotInitialized {
		return &clairerror.ErrNotInitialized{msg + err.Error()}
	}

	pool, err := postgres.Connect(ctx, cfg.Indexer.ConnString, "libindex")
	if err != nil {
		return nil, mkErr(err)
	}
	store, err := postgres.InitPostgresIndexerStore(ctx, pool, cfg.Indexer.Migrations)
	if err != nil {
		return nil, mkErr(err)
	}
	locker, err := ctxlock.New(ctx, pool)
	if err != nil {
		return nil, mkErr(err)
	}

	opts := libindex.Options{
		Store:                store,
		Locker:               locker,
		ScanLockRetry:        time.Duration(cfg.Indexer.ScanLockRetry) * time.Second,
		LayerScanConcurrency: cfg.Indexer.LayerScanConcurrency,
	}
	if cfg.Indexer.Scanner.Package != nil {
		opts.ScannerConfig.Package = make(map[string]func(interface{}) error, len(cfg.Indexer.Scanner.Package))
		for name, node := range cfg.Indexer.Scanner.Package {
			node := node
			opts.ScannerConfig.Package[name] = func(v interface{}) error {
				b, err := json.Marshal(node)
				if err != nil {
					return err
				}
				return json.Unmarshal(b, v)
			}
		}
	}
	if cfg.Indexer.Scanner.Dist != nil {
		opts.ScannerConfig.Dist = make(map[string]func(interface{}) error, len(cfg.Indexer.Scanner.Dist))
		for name, node := range cfg.Indexer.Scanner.Dist {
			node := node
			opts.ScannerConfig.Dist[name] = func(v interface{}) error {
				b, err := json.Marshal(node)
				if err != nil {
					return err
				}
				return json.Unmarshal(b, v)
			}
		}
	}
	if cfg.Indexer.Scanner.Repo != nil {
		opts.ScannerConfig.Repo = make(map[string]func(interface{}) error, len(cfg.Indexer.Scanner.Repo))
		for name, node := range cfg.Indexer.Scanner.Repo {
			node := node
			opts.ScannerConfig.Repo[name] = func(v interface{}) error {
				b, err := json.Marshal(node)
				if err != nil {
					return err
				}
				return json.Unmarshal(b, v)
			}
		}
	}
	c, err := httputil.NewClient(ctx, cfg.Indexer.Airgap)
	if err != nil {
		return nil, mkErr(err)
	}

	opts.FetchArena = libindex.NewRemoteFetchArena(c, "")

	s, err := libindex.New(ctx, &opts, c)
	if err != nil {
		return nil, mkErr(err)
	}
	return s, nil
}

func remoteIndexer(ctx context.Context, cfg *config.Config, addr string) (indexer.Service, error) {
	const msg = "failed to initialize indexer client: "
	mkErr := func(err error) *clairerror.ErrNotInitialized {
		return &clairerror.ErrNotInitialized{msg + err.Error()}
	}
	rc, err := remoteClient(ctx, cfg, intraserviceClaim, addr)
	if err != nil {
		return nil, mkErr(err)
	}
	return rc, nil
}

func remoteClient(ctx context.Context, cfg *config.Config, claim jwt.Claims, addr string) (*client.HTTP, error) {
	c, err := httputil.NewClient(ctx, false) // ???
	if err != nil {
		return nil, err
	}
	opts := []client.Option{client.WithAddr(addr), client.WithClient(c)}
	if cfg.Auth.Any() {
		s, err := httputil.NewSigner(ctx, cfg, claim)
		if err != nil {
			return nil, err
		}
		opts = append(opts, client.WithSigner(s))
	}
	return client.NewHTTP(ctx, opts...)
}

func localMatcher(ctx context.Context, cfg *config.Config) (matcher.Service, error) {
	const msg = "failed to initialize matcher: "
	mkErr := func(err error) *clairerror.ErrNotInitialized {
		return &clairerror.ErrNotInitialized{
			Msg: msg + err.Error(),
		}
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	// Some servers return weak validators when the Content-Encoding is not
	// "identity". Setting this prevents automatically negotiating up to "gzip".
	tr.DisableCompression = true
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return nil, err
	}
	cl := &http.Client{
		Jar:       jar,
		Transport: httputil.RateLimiter(tr),
	}
	updaterConfigs := make(map[string]driver.ConfigUnmarshaler)
	for name, node := range cfg.Updaters.Config {
		node := node
		updaterConfigs[name] = func(v interface{}) error {
			b, err := json.Marshal(node)
			if err != nil {
				return err
			}
			return json.Unmarshal(b, v)
		}
	}
	matcherConfigs := make(map[string]driver.MatcherConfigUnmarshaler)
	for name, node := range cfg.Matchers.Config {
		node := node
		matcherConfigs[name] = func(v interface{}) error {
			b, err := json.Marshal(node)
			if err != nil {
				return err
			}
			return json.Unmarshal(b, v)
		}
	}
	pool, err := postgres.Connect(ctx, cfg.Matcher.ConnString, "libvuln")
	if err != nil {
		return nil, mkErr(err)
	}
	store, err := postgres.InitPostgresMatcherStore(ctx, pool, cfg.Matcher.Migrations)
	if err != nil {
		return nil, mkErr(err)
	}
	locker, err := ctxlock.New(ctx, pool)
	if err != nil {
		return nil, mkErr(err)
	}

	s, err := libvuln.New(ctx, &libvuln.Options{
		Store:           store,
		Locker:          locker,
		UpdaterSets:     cfg.Updaters.Sets,
		UpdateInterval:  time.Duration(cfg.Matcher.Period),
		UpdaterConfigs:  updaterConfigs,
		UpdateRetention: cfg.Matcher.UpdateRetention,
		MatcherNames:    cfg.Matchers.Names,
		MatcherConfigs:  matcherConfigs,
		Client:          cl,
		Enrichers: []driver.Enricher{
			&cvss.Enricher{},
		},
	})
	if err != nil {
		return nil, mkErr(err)
	}
	return s, nil
}

func remoteMatcher(ctx context.Context, cfg *config.Config, addr string) (matcher.Service, error) {
	const msg = "failed to initialize matcher client: "
	mkErr := func(err error) *clairerror.ErrNotInitialized {
		return &clairerror.ErrNotInitialized{msg + err.Error()}
	}
	rc, err := remoteClient(ctx, cfg, intraserviceClaim, addr)
	if err != nil {
		return nil, mkErr(err)
	}
	return rc, nil
}

func localNotifier(ctx context.Context, cfg *config.Config, i indexer.Service, m matcher.Service) (notifier.Service, error) {
	const msg = "failed to initialize notifier: "
	mkErr := func(err error) *clairerror.ErrNotInitialized {
		return &clairerror.ErrNotInitialized{
			Msg: msg + err.Error(),
		}
	}

	c, err := httputil.NewClient(ctx, false) // No airgap flag.
	if err != nil {
		return nil, mkErr(err)
	}
	signer, err := httputil.NewSigner(ctx, cfg, notifierClaim)
	if err != nil {
		return nil, mkErr(err)
	}

	ncfg := &cfg.Notifier
	poolcfg, err := pgxpool.ParseConfig(ncfg.ConnString)
	if err != nil {
		return nil, mkErr(err)
	}
	if cfg.Notifier.Migrations {
		if err := notifierpg.Init(ctx, poolcfg.ConnConfig); err != nil {
			return nil, mkErr(err)
		}
	}
	pool, err := pgxpool.ConnectConfig(ctx, poolcfg)
	if err != nil {
		return nil, mkErr(err)
	}
	store := notifierpg.NewStore(pool)
	locks, err := ctxlock.New(ctx, pool)
	if err != nil {
		return nil, mkErr(err)
	}

	s, err := service.New(ctx, store, locks, service.Opts{
		DeliveryInterval: time.Duration(cfg.Notifier.DeliveryInterval),
		Indexer:          i,
		Matcher:          m,
		Client:           c,
		Signer:           signer,
		PollInterval:     time.Duration(cfg.Notifier.PollInterval),
		DisableSummary:   cfg.Notifier.DisableSummary,
		Webhook:          cfg.Notifier.Webhook,
		AMQP:             cfg.Notifier.AMQP,
		STOMP:            cfg.Notifier.STOMP,
	})
	switch {
	case err == nil:
	case errors.Is(err, service.ErrNoDelivery):
		zlog.Info(ctx).AnErr("reason", err).Msg("notifier disabled")
		return nil, nil
	default:
		return nil, mkErr(err)
	}
	go func() {
		if err := s.Run(ctx); err != context.Canceled {
			zlog.Error(ctx).Err(err).Msg("unexpected notifier error")
		}
	}()
	return s, nil
}
