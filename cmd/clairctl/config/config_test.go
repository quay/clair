package config

import (
	"fmt"
	"os"
	"testing"

	"github.com/jgsqware/clairctl/test"
	"github.com/spf13/viper"

	"gopkg.in/yaml.v2"
)

const defaultValues = `
clair:
  uri: http://localhost
  port: 6060
  healthport: 6061
  report:
    path: reports
    format: html
auth:
  insecureskipverify: true
clairctl:
  ip: ""
  tempfolder: /tmp/clairctl
  port: 0
`

const customValues = `
clair:
  uri: http://clair
  port: 6061
  healthport: 6062
  report:
    path: reports/test
    format: json
auth:
  insecureskipverify: false
clairctl:
  ip: "localhost"
  tempfolder: /tmp/clairctl/test
  port: 64157
`

func TestInitDefault(t *testing.T) {
	Init("", "INFO")

	cfg := values()

	var expected config
	err := yaml.Unmarshal([]byte(defaultValues), &expected)
	if err != nil {
		t.Fatal(err)
	}

	if cfg != expected {
		t.Error("Default values are not correct")
	}
	viper.Reset()
}

func TestInitCustomLocal(t *testing.T) {
	tmpfile := test.CreateConfigFile(customValues, "clairctl.yml", ".")
	defer os.Remove(tmpfile) // clean up
	fmt.Println(tmpfile)
	Init("", "INFO")

	cfg := values()

	var expected config
	err := yaml.Unmarshal([]byte(customValues), &expected)
	if err != nil {
		t.Fatal(err)
	}

	if cfg != expected {
		t.Error("values are not correct")
	}
	viper.Reset()
}

func TestInitCustomHome(t *testing.T) {
	tmpfile := test.CreateConfigFile(customValues, "clairctl.yml", ClairctlHome())
	defer os.Remove(tmpfile) // clean up
	fmt.Println(tmpfile)
	Init("", "INFO")

	cfg := values()

	var expected config
	err := yaml.Unmarshal([]byte(customValues), &expected)
	if err != nil {
		t.Fatal(err)
	}

	if cfg != expected {
		t.Error("values are not correct")
	}
	viper.Reset()
}

func TestInitCustom(t *testing.T) {
	tmpfile := test.CreateConfigFile(customValues, "clairctl.yml", "/tmp")
	defer os.Remove(tmpfile) // clean up
	fmt.Println(tmpfile)
	Init(tmpfile, "INFO")

	cfg := values()

	var expected config
	err := yaml.Unmarshal([]byte(customValues), &expected)
	if err != nil {
		t.Fatal(err)
	}

	if cfg != expected {
		t.Error("values are not correct")
	}
	viper.Reset()
}
