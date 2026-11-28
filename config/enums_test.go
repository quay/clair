package config_test

import (
	"testing"

	"github.com/quay/clair/config"
)

func TestEnumMarshal(t *testing.T) {
	t.Run("LogLevel", func(t *testing.T) {
		type testcase struct {
			Level  config.LogLevel
			String string
		}
		tt := []testcase{
			{Level: config.TraceLog, String: "trace"},
			{Level: config.DebugColorLog, String: "debug-color"},
			{Level: config.DebugLog, String: "debug"},
			{Level: config.InfoLog, String: "info"},
			{Level: config.WarnLog, String: "warn"},
			{Level: config.ErrorLog, String: "error"},
			{Level: config.FatalLog, String: "fatal"},
			{Level: config.PanicLog, String: "panic"},
		}
		t.Run("Marshal", func(t *testing.T) {
			for _, tc := range tt {
				m, err := tc.Level.MarshalText()
				if err != nil {
					t.Error(err)
					continue
				}
				if got, want := string(m), tc.String; got != want {
					t.Errorf("got: %q, want: %q", got, want)
				}
			}
		})
		t.Run("Unmarshal", func(t *testing.T) {
			for _, tc := range tt {
				var got config.LogLevel
				if err := got.UnmarshalText([]byte(tc.String)); err != nil {
					t.Error(err)
					continue
				}
				if want := tc.Level; got != want {
					t.Errorf("got: %q, want: %q", got, want)
				}
			}
		})
	})
}
