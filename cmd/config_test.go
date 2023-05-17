package cmd_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/clair/config"

	"github.com/quay/clair/v4/cmd"
)

func TestLoadConfig(t *testing.T) {
	ms, err := filepath.Glob(`testdata/*/config.*[^d]`)
	if err != nil {
		panic("programmer error")
	}
	for _, m := range ms {
		name := filepath.Base(filepath.Dir(m))
		t.Run(name, func(t *testing.T) {
			wantpath := filepath.Join(filepath.Dir(m), "want.json")
			wf, err := os.Open(wantpath)
			if err != nil {
				t.Fatal(err)
			}
			defer wf.Close()
			var got, want config.Config
			if err := json.NewDecoder(wf).Decode(&want); err != nil {
				t.Error(err)
			}
			if err := cmd.LoadConfig(&got, m, true); err != nil {
				t.Error(err)
			}
			if !cmp.Equal(got, want) {
				t.Error(cmp.Diff(got, want))
			}
		})
	}
	ms, err = filepath.Glob(`testdata/Error/*[^d]`)
	if err != nil {
		panic("programmer error")
	}
	t.Run("Error", func(t *testing.T) {
		for _, m := range ms {
			name := filepath.Base(m)
			name = strings.TrimSuffix(name, filepath.Ext(name))
			t.Run(name, func(t *testing.T) {
				var got config.Config
				err := cmd.LoadConfig(&got, m, false)
				t.Log(err)
				if err == nil {
					t.Fail()
				}
			})
		}
	})
}
