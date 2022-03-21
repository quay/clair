package config_test

import (
	"bytes"
	"testing"

	"github.com/quay/clair/config"
)

func TestEnumMarshal(t *testing.T) {
	t.Run("LogLevel", func(t *testing.T) {
		tt := [][]byte{
			[]byte("info"),
			[]byte("debug-color"),
			[]byte("debug"),
			[]byte("warn"),
			[]byte("error"),
			[]byte("fatal"),
			[]byte("panic"),
		}
		t.Run("Marshal", func(t *testing.T) {
			for i, want := range tt {
				l := config.LogLevel(i)
				got, err := l.MarshalText()
				if err != nil {
					t.Error(err)
					continue
				}
				if !bytes.Equal(got, want) {
					t.Errorf("got: %q, want: %q", got, want)
				}
			}
		})
		t.Run("Unmarshal", func(t *testing.T) {
			for want, in := range tt {
				var l config.LogLevel
				if err := l.UnmarshalText(in); err != nil {
					t.Error(err)
					continue
				}
				if got := int(l); got != want {
					t.Errorf("got: %q, want: %q", got, want)
				}
			}
		})
	})
}
