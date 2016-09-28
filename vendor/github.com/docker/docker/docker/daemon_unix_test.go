// +build daemon,!windows

package main

import (
	"io/ioutil"
	"testing"

	"github.com/docker/docker/cli"
	"github.com/docker/docker/daemon"
	"github.com/docker/docker/opts"
	"github.com/docker/docker/pkg/mflag"
)

func TestLoadDaemonConfigWithNetwork(t *testing.T) {
	c := &daemon.Config{}
	common := &cli.CommonFlags{}
	flags := mflag.NewFlagSet("test", mflag.ContinueOnError)
	flags.String([]string{"-bip"}, "", "")
	flags.String([]string{"-ip"}, "", "")

	f, err := ioutil.TempFile("", "docker-config-")
	if err != nil {
		t.Fatal(err)
	}

	configFile := f.Name()
	f.Write([]byte(`{"bip": "127.0.0.2", "ip": "127.0.0.1"}`))
	f.Close()

	loadedConfig, err := loadDaemonCliConfig(c, flags, common, configFile)
	if err != nil {
		t.Fatal(err)
	}
	if loadedConfig == nil {
		t.Fatalf("expected configuration %v, got nil", c)
	}
	if loadedConfig.IP != "127.0.0.2" {
		t.Fatalf("expected IP 127.0.0.2, got %v", loadedConfig.IP)
	}
	if loadedConfig.DefaultIP.String() != "127.0.0.1" {
		t.Fatalf("expected DefaultIP 127.0.0.1, got %s", loadedConfig.DefaultIP)
	}
}

func TestLoadDaemonConfigWithMapOptions(t *testing.T) {
	c := &daemon.Config{}
	common := &cli.CommonFlags{}
	flags := mflag.NewFlagSet("test", mflag.ContinueOnError)

	flags.Var(opts.NewNamedMapOpts("cluster-store-opts", c.ClusterOpts, nil), []string{"-cluster-store-opt"}, "")
	flags.Var(opts.NewNamedMapOpts("log-opts", c.LogConfig.Config, nil), []string{"-log-opt"}, "")

	f, err := ioutil.TempFile("", "docker-config-")
	if err != nil {
		t.Fatal(err)
	}

	configFile := f.Name()
	f.Write([]byte(`{
		"cluster-store-opts": {"kv.cacertfile": "/var/lib/docker/discovery_certs/ca.pem"},
		"log-opts": {"tag": "test"}
}`))
	f.Close()

	loadedConfig, err := loadDaemonCliConfig(c, flags, common, configFile)
	if err != nil {
		t.Fatal(err)
	}
	if loadedConfig == nil {
		t.Fatal("expected configuration, got nil")
	}
	if loadedConfig.ClusterOpts == nil {
		t.Fatal("expected cluster options, got nil")
	}

	expectedPath := "/var/lib/docker/discovery_certs/ca.pem"
	if caPath := loadedConfig.ClusterOpts["kv.cacertfile"]; caPath != expectedPath {
		t.Fatalf("expected %s, got %s", expectedPath, caPath)
	}

	if loadedConfig.LogConfig.Config == nil {
		t.Fatal("expected log config options, got nil")
	}
	if tag := loadedConfig.LogConfig.Config["tag"]; tag != "test" {
		t.Fatalf("expected log tag `test`, got %s", tag)
	}
}

func TestLoadDaemonConfigWithTrueDefaultValues(t *testing.T) {
	c := &daemon.Config{}
	common := &cli.CommonFlags{}
	flags := mflag.NewFlagSet("test", mflag.ContinueOnError)
	flags.BoolVar(&c.EnableUserlandProxy, []string{"-userland-proxy"}, true, "")

	f, err := ioutil.TempFile("", "docker-config-")
	if err != nil {
		t.Fatal(err)
	}

	if err := flags.ParseFlags([]string{}, false); err != nil {
		t.Fatal(err)
	}

	configFile := f.Name()
	f.Write([]byte(`{
		"userland-proxy": false
}`))
	f.Close()

	loadedConfig, err := loadDaemonCliConfig(c, flags, common, configFile)
	if err != nil {
		t.Fatal(err)
	}
	if loadedConfig == nil {
		t.Fatal("expected configuration, got nil")
	}

	if loadedConfig.EnableUserlandProxy {
		t.Fatal("expected userland proxy to be disabled, got enabled")
	}

	// make sure reloading doesn't generate configuration
	// conflicts after normalizing boolean values.
	err = daemon.ReloadConfiguration(configFile, flags, func(reloadedConfig *daemon.Config) {
		if reloadedConfig.EnableUserlandProxy {
			t.Fatal("expected userland proxy to be disabled, got enabled")
		}
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestLoadDaemonConfigWithTrueDefaultValuesLeaveDefaults(t *testing.T) {
	c := &daemon.Config{}
	common := &cli.CommonFlags{}
	flags := mflag.NewFlagSet("test", mflag.ContinueOnError)
	flags.BoolVar(&c.EnableUserlandProxy, []string{"-userland-proxy"}, true, "")

	f, err := ioutil.TempFile("", "docker-config-")
	if err != nil {
		t.Fatal(err)
	}

	if err := flags.ParseFlags([]string{}, false); err != nil {
		t.Fatal(err)
	}

	configFile := f.Name()
	f.Write([]byte(`{}`))
	f.Close()

	loadedConfig, err := loadDaemonCliConfig(c, flags, common, configFile)
	if err != nil {
		t.Fatal(err)
	}
	if loadedConfig == nil {
		t.Fatal("expected configuration, got nil")
	}

	if !loadedConfig.EnableUserlandProxy {
		t.Fatal("expected userland proxy to be enabled, got disabled")
	}
}
