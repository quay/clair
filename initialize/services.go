package initialize

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"time"

	"github.com/quay/claircore/enricher/cvss"
	"github.com/quay/claircore/libindex"
	"github.com/quay/claircore/libvuln"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"
	"golang.org/x/net/publicsuffix"
	"gopkg.in/square/go-jose.v2/jwt"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/config"
	"github.com/quay/clair/v4/httptransport"
	"github.com/quay/clair/v4/httptransport/client"
	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/internal/httputil"
	"github.com/quay/clair/v4/matcher"
	notifier "github.com/quay/clair/v4/notifier/service"
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
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "initialize/Services"),
	)
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

func localIndexer(ctx context.Context, cfg *config.Config) (indexer.Service, error) {
	const msg = "failed to initialize indexer: "
	mkErr := func(err error) *clairerror.ErrNotInitialized {
		return &clairerror.ErrNotInitialized{msg + err.Error()}
	}
	opts := libindex.Opts{
		ConnString:           cfg.Indexer.ConnString,
		ScanLockRetry:        time.Duration(cfg.Indexer.ScanLockRetry) * time.Second,
		LayerScanConcurrency: cfg.Indexer.LayerScanConcurrency,
		Migrations:           cfg.Indexer.Migrations,
		Airgap:               cfg.Indexer.Airgap,
	}
	if cfg.Indexer.Scanner.Package != nil {
		opts.ScannerConfig.Package = make(map[string]func(interface{}) error, len(cfg.Indexer.Scanner.Package))
		for name, node := range cfg.Indexer.Scanner.Package {
			opts.ScannerConfig.Package[name] = node.Decode
		}
	}
	if cfg.Indexer.Scanner.Dist != nil {
		opts.ScannerConfig.Dist = make(map[string]func(interface{}) error, len(cfg.Indexer.Scanner.Dist))
		for name, node := range cfg.Indexer.Scanner.Dist {
			opts.ScannerConfig.Dist[name] = node.Decode
		}
	}
	if cfg.Indexer.Scanner.Repo != nil {
		opts.ScannerConfig.Repo = make(map[string]func(interface{}) error, len(cfg.Indexer.Scanner.Repo))
		for name, node := range cfg.Indexer.Scanner.Repo {
			opts.ScannerConfig.Repo[name] = node.Decode
		}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	// Use an empty claim because this shouldn't be talking to something that
	// needs preconfigured authz. Callers should be providing credentials to the
	// indexing process in the submitted manifest.
	c, _, err := cfg.Client(tr, nil)
	if err != nil {
		return nil, mkErr(err)
	}

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
	tr := http.DefaultTransport.(*http.Transport).Clone()
	c, auth, err := cfg.Client(tr, &claim)
	switch {
	case err != nil:
		return nil, err
	case !auth && cfg.Auth.Any():
		return nil, errors.New("client authorization required but not provided")
	default: // OK
	}
	return client.NewHTTP(ctx, client.WithAddr(addr), client.WithClient(c))
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
		updaterConfigs[name] = node.Decode
	}
	matcherConfigs := make(map[string]driver.MatcherConfigUnmarshaler)
	for name, node := range cfg.Matchers.Config {
		matcherConfigs[name] = node.Decode
	}
	s, err := libvuln.New(ctx, &libvuln.Opts{
		MaxConnPool:     int32(cfg.Matcher.MaxConnPool),
		ConnString:      cfg.Matcher.ConnString,
		Migrations:      cfg.Matcher.Migrations,
		UpdaterSets:     cfg.Updaters.Sets,
		UpdateInterval:  cfg.Matcher.Period,
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

	tr := http.DefaultTransport.(*http.Transport).Clone()
	c, _, err := cfg.Client(tr, &notifierClaim)
	if err != nil {
		return nil, mkErr(err)
	}

	s, err := notifier.New(ctx, notifier.Opts{
		DeliveryInterval: cfg.Notifier.DeliveryInterval,
		ConnString:       cfg.Notifier.ConnString,
		Indexer:          i,
		Matcher:          m,
		Client:           c,
		Migrations:       cfg.Notifier.Migrations,
		PollInterval:     cfg.Notifier.PollInterval,
		DisableSummary:   cfg.Notifier.DisableSummary,
		Webhook:          cfg.Notifier.Webhook,
		AMQP:             cfg.Notifier.AMQP,
		STOMP:            cfg.Notifier.STOMP,
	})
	if err != nil {
		return nil, mkErr(err)
	}
	return s, nil
}
