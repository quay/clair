package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gopkg.in/yaml.v3"
)

type configTestcase struct {
	File string
	Mode string
	Err  error
}

func (tc *configTestcase) Run(t *testing.T) {
	name := strings.TrimSuffix(filepath.Base(tc.File), filepath.Ext(tc.File))
	t.Run(strings.Title(name), func(t *testing.T) {
		f, err := os.Open(tc.File)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()

		var cfg Config
		if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
			t.Error(err)
		}
		cfg.Mode = tc.Mode

		if err := Validate(&cfg); !cmp.Equal(err, tc.Err, cmpopts.EquateErrors()) {
			t.Error(cmp.Diff(err, tc.Err, cmpopts.EquateErrors()))
		}
	})
}

func TestNotifier(t *testing.T) {
	tt := []configTestcase{
		{
			File: "testdata/combo.yaml",
			Mode: "combo",
		},
		{
			File: "testdata/no-notifier.yaml",
			Mode: "notifier",
			Err:  errNeedDelivery,
		},
	}
	for _, tc := range tt {
		tc.Run(t)
	}
}
