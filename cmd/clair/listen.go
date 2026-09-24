package main

import (
	"cmp"

	"github.com/quay/clair/config"
)

// GetIntrospectionAddress returns the address in the configuration.
func getIntrospectionAddress(cfg *config.Config) string {
	icfg := &cfg.Introspection
	return cmp.Or(icfg.Address, cfg.IntrospectionAddr)
}

// GetAPIv1Address returns the address in the configuration.
func getAPIv1Address(cfg *config.Config) string {
	apicfg := &cfg.API.V1
	return cmp.Or(apicfg.Address, cfg.HTTPListenAddr)
}
