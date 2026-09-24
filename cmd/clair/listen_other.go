//go:build !linux

package main

import (
	"context"
	"net"

	"github.com/quay/clair/config"
)

// ListenAPI returns a listener to serve the API on.
func listenAPI(_ context.Context, cfg *config.Config) (net.Listener, error) {
	return net.Listen(cfg.API.V1.Network, getAPIv1Address(cfg))
}

// ListenIntrospection returns a listener to serve the Introspection services on.
func listenIntrospection(_ context.Context, cfg *config.Config) (net.Listener, error) {
	return net.Listen(cfg.Introspection.Network, getIntrospectionAddress(cfg))
}
