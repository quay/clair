package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFlagParsing(t *testing.T) {
	configname := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configname, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("Empty", func(t *testing.T) {
		var f Flags
		err := f.Parse([]string{})
		t.Logf("error: %v", err)
		if err == nil {
			t.Fail()
		}
		if s := err.Error(); !strings.Contains(s, "CLAIR_CONF") || !strings.Contains(s, "CLAIR_MODE") {
			t.Fail()
		}
	})

	t.Run("MissingMode", func(t *testing.T) {
		var f Flags
		err := f.Parse([]string{"-conf", configname})
		t.Logf("error: %v", err)
		if err == nil {
			t.Fail()
		}
		if s := err.Error(); !strings.Contains(s, "CLAIR_MODE") {
			t.Fail()
		}
	})

	t.Run("MissingConfig", func(t *testing.T) {
		var f Flags
		err := f.Parse([]string{"-mode", "combo"})
		t.Logf("error: %v", err)
		if err == nil {
			t.Fail()
		}
		if s := err.Error(); !strings.Contains(s, "CLAIR_CONF") {
			t.Fail()
		}
	})

	t.Run("Environment", func(t *testing.T) {
		t.Setenv("CLAIR_MODE", "combo")
		t.Setenv("CLAIR_CONF", configname)
		var f Flags
		err := f.Parse([]string{})
		t.Logf("error: %v", err)
		if err != nil {
			t.Fail()
		}
	})

	t.Run("CPUProfile", func(t *testing.T) {
		t.Setenv("CLAIR_MODE", "combo")
		t.Setenv("CLAIR_CONF", configname)
		var f Flags
		err := f.Parse([]string{"-cpuprofile", "/dev/null"})
		t.Logf("error: %v", err)
		if err != nil {
			t.Fail()
		}
		t.Logf("cpuprofile: %q", f.CPUProfile)
		if got, want := f.CPUProfile, "/dev/null"; got != want {
			t.Fail()
		}
	})

	t.Run("MemProfile", func(t *testing.T) {
		t.Setenv("CLAIR_MODE", "combo")
		t.Setenv("CLAIR_CONF", configname)
		var f Flags
		err := f.Parse([]string{"-memprofile", "/dev/null"})
		t.Logf("error: %v", err)
		if err != nil {
			t.Fail()
		}
		t.Logf("memprofile: %q", f.MemProfile)
		if got, want := f.MemProfile, "/dev/null"; got != want {
			t.Fail()
		}
	})
}
