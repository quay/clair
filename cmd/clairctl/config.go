package main

import (
	"os"

	"gopkg.in/yaml.v3"

	"github.com/quay/clair/v4/config"
)

func loadConfig(n string) (*config.Config, error) {
	f, err := os.Open(n)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg config.Config
	if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, err
	}
	// Can't use validate, because we're not running in a server "mode".
	return &cfg, nil
}
