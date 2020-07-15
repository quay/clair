package initialize

import (
	"context"

	"github.com/quay/clair/v4/config"
	"github.com/quay/clair/v4/httptransport"
	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/introspection"
	"github.com/quay/clair/v4/matcher"
	notifier "github.com/quay/clair/v4/notifier/service"
)

type Init struct {
	// configuration provided
	conf config.Config
	// a global ctx with an embedded logger
	// enables downstream logging and global application cancelation
	GlobalCTX context.Context
	// A global cancel func providing cancelation to all
	// routines passed GlobalCTX
	GlobalCancel context.CancelFunc
	// A local or remote Indexer service
	Indexer indexer.Service
	// A local or remote Matcher service
	Matcher matcher.Service
	// A local or remote Notifier service
	Notifier notifier.Service
	// The primary http server implementing Clair's functionality
	HttpTransport *httptransport.Server
	// Introspection provides metrics and trace exporters,
	// a pprof diagnostics server, and a healthz endpoint
	Introspection *introspection.Server
}

// New wil begin an init process and return
// an Init object on success
func New(conf config.Config) (*Init, error) {
	i := &Init{
		conf: conf,
	}

	// init logging. GlobalCTX and GlobalCancel
	// will be initialized here as well.
	err := i.Logging()
	if err != nil {
		return nil, err
	}

	// init services. Indexer and Matcher
	// fields will be initialized here.
	err = i.Services()
	if err != nil {
		return nil, err
	}

	// init introspection.
	// a returned nil means no introspection configured
	// a returned error means initialization failed
	i.Introspection, err = introspection.New(i.GlobalCTX, conf, nil)
	if err != nil {
		return nil, err
	}

	// init http transport.
	// init will either succeed or fail.
	i.HttpTransport, err = httptransport.New(i.GlobalCTX, conf, i.Indexer, i.Matcher, i.Notifier)
	if err != nil {
		return nil, err
	}

	return i, nil
}
