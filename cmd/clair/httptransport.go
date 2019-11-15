package main

import (
	"net/http"

	"github.com/quay/clair/v4/config"
)

// httptransport configures an http server according to Clair's operation
// mode.
func httptransport(mode Mode, conf config.Config) (*http.Server, error) {
	switch mode {
	case Indexer:

	}
}
