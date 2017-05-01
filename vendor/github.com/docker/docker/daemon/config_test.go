package daemon

import (
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/docker/docker/opts"
	"github.com/docker/docker/pkg/testutil/assert"
	"github.com/spf13/pflag"
)

func TestDaemonConfigurationNotFound(t *testing.T) {
	_, err := MergeDaemonConfigurations(&Config{}, nil, "/tmp/foo-bar-baz-docker")
	if err == nil || !os.IsNotExist(err) {
		t.Fatalf("expected does not exist error, got %v", err)
	}
}

func TestDaemonBrokenConfiguration(t *testing.T) {
	f, err := ioutil.TempFile("", "docker-config-")
	if err != nil {
		t.Fatal(err)
	}

	configFile := f.Name()
	f.Write([]byte(`{"Debug": tru`))
	f.Close()

	_, err = MergeDaemonConfigurations(&Config{}, nil, configFile)
	if err == nil {
		t.Fatalf("expected error, got %v", err)
	}
}

func TestParseClusterAdvertiseSettings(t *testing.T) {
	if runtime.GOOS == "solaris" {
		t.Skip("ClusterSettings not supported on Solaris\n")
	}
	_, err := parseClusterAdvertiseSettings("something", "")
	if err != errDiscoveryDisabled {
		t.Fatalf("expected discovery disabled error, got %v\n", err)
	}

	_, err = parseClusterAdvertiseSettings("", "something")
	if err == nil {
		t.Fatalf("expected discovery store error, got %v\n", err)
	}

	_, err = parseClusterAdvertiseSettings("etcd", "127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
}

func TestFindConfigurationConflicts(t *testing.T) {
	config := map[string]interface{}{"authorization-plugins": "foobar"}
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)

	flags.String("authorization-plugins", "", "")
	assert.NilError(t, flags.Set("authorization-plugins", "asdf"))

	assert.Error(t,
		findConfigurationConflicts(config, flags),
		"authorization-plugins: (from flag: asdf, from file: foobar)")
}

func TestFindConfigurationConflictsWithNamedOptions(t *testing.T) {
	config := map[string]interface{}{"hosts": []string{"qwer"}}
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)

	var hosts []string
	flags.VarP(opts.NewNamedListOptsRef("hosts", &hosts, opts.ValidateHost), "host", "H", "Daemon socket(s) to connect to")
	assert.NilError(t, flags.Set("host", "tcp://127.0.0.1:4444"))
	assert.NilError(t, flags.Set("host", "unix:///var/run/docker.sock"))

	assert.Error(t, findConfigurationConflicts(config, flags), "hosts")
}

func TestDaemonConfigurationMergeConflicts(t *testing.T) {
	f, err := ioutil.TempFile("", "docker-config-")
	if err != nil {
		t.Fatal(err)
	}

	configFile := f.Name()
	f.Write([]byte(`{"debug": true}`))
	f.Close()

	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.Bool("debug", false, "")
	flags.Set("debug", "false")

	_, err = MergeDaemonConfigurations(&Config{}, flags, configFile)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "debug") {
		t.Fatalf("expected debug conflict, got %v", err)
	}
}

func TestDaemonConfigurationMergeConflictsWithInnerStructs(t *testing.T) {
	f, err := ioutil.TempFile("", "docker-config-")
	if err != nil {
		t.Fatal(err)
	}

	configFile := f.Name()
	f.Write([]byte(`{"tlscacert": "/etc/certificates/ca.pem"}`))
	f.Close()

	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.String("tlscacert", "", "")
	flags.Set("tlscacert", "~/.docker/ca.pem")

	_, err = MergeDaemonConfigurations(&Config{}, flags, configFile)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "tlscacert") {
		t.Fatalf("expected tlscacert conflict, got %v", err)
	}
}

func TestFindConfigurationConflictsWithUnknownKeys(t *testing.T) {
	config := map[string]interface{}{"tls-verify": "true"}
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)

	flags.Bool("tlsverify", false, "")
	err := findConfigurationConflicts(config, flags)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "the following directives don't match any configuration option: tls-verify") {
		t.Fatalf("expected tls-verify conflict, got %v", err)
	}
}

func TestFindConfigurationConflictsWithMergedValues(t *testing.T) {
	var hosts []string
	config := map[string]interface{}{"hosts": "tcp://127.0.0.1:2345"}
	flags := pflag.NewFlagSet("base", pflag.ContinueOnError)
	flags.VarP(opts.NewNamedListOptsRef("hosts", &hosts, nil), "host", "H", "")

	err := findConfigurationConflicts(config, flags)
	if err != nil {
		t.Fatal(err)
	}

	flags.Set("host", "unix:///var/run/docker.sock")
	err = findConfigurationConflicts(config, flags)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "hosts: (from flag: [unix:///var/run/docker.sock], from file: tcp://127.0.0.1:2345)") {
		t.Fatalf("expected hosts conflict, got %v", err)
	}
}

func TestValidateConfiguration(t *testing.T) {
	c1 := &Config{
		CommonConfig: CommonConfig{
			Labels: []string{"one"},
		},
	}

	err := ValidateConfiguration(c1)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	c2 := &Config{
		CommonConfig: CommonConfig{
			Labels: []string{"one=two"},
		},
	}

	err = ValidateConfiguration(c2)
	if err != nil {
		t.Fatalf("expected no error, got error %v", err)
	}

	c3 := &Config{
		CommonConfig: CommonConfig{
			DNS: []string{"1.1.1.1"},
		},
	}

	err = ValidateConfiguration(c3)
	if err != nil {
		t.Fatalf("expected no error, got error %v", err)
	}

	c4 := &Config{
		CommonConfig: CommonConfig{
			DNS: []string{"1.1.1.1o"},
		},
	}

	err = ValidateConfiguration(c4)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	c5 := &Config{
		CommonConfig: CommonConfig{
			DNSSearch: []string{"a.b.c"},
		},
	}

	err = ValidateConfiguration(c5)
	if err != nil {
		t.Fatalf("expected no error, got error %v", err)
	}

	c6 := &Config{
		CommonConfig: CommonConfig{
			DNSSearch: []string{"123456"},
		},
	}

	err = ValidateConfiguration(c6)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
