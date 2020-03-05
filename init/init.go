package initialize

import (
	"context"

	"github.com/quay/clair/v4/config"
	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/matcher"
)

const (
	Version = "v4.0.0-rc01"
)

// Init handles all initialization necessary
// to start Clair
type Init struct {
	// Configuration provied to clair on invocation.
	conf config.Config
	// ctx with a logger embeded.
	// this ctx will be provided to other spawned routines
	GlobalCTX context.Context
	// the global cancel func providing cancelation to all
	// children routine in flight
	GlobalCancel context.CancelFunc
	// A local or remote Indexer service
	Indexer indexer.Service
	// A local or remote Matcher service
	Matcher matcher.Service
	// An http server ready to ListenAndServe given the provided config
	HttpTransport *HttpTransport
}

// New will begin an init process and return
// an Init object on success
func New(conf config.Config) (*Init, error) {
	i := &Init{
		conf: conf,
	}

	// init logging
	err := i.Logging()
	if err != nil {
		return nil, err
	}

	// init services
	err = i.Services()
	if err != nil {
		return nil, err
	}

	// init http transport
	i.HttpTransport, err = NewHttpTransport(i.GlobalCTX, i.conf, i.Indexer, i.Matcher)
	if err != nil {
		return nil, err
	}

	return i, nil
}
