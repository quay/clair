package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/quay/clair/v4/config"
)

// ConfValue implements the flag.Value interface
//
// ConfValue parses a filesystem path and confirms it exists and is readable.
// If these conditions do not pass a error is returned.
type ConfValue struct {
	file *os.File
}

func (v *ConfValue) String() string {
	if v.file == nil {
		return ""
	}
	return v.file.Name()
}

func (v *ConfValue) Set(s string) error {
	s = filepath.Clean(s)
	if s == "." {
		return fmt.Errorf("most provide a path to a file")
	}

	f, err := os.Open(s)
	if err != nil {
		return fmt.Errorf("failed to open config file at %s: %w", s, err)
	}
	v.file = f
	return nil
}

const (
	_ ConfMode = iota
	ModeCombo
	ModeIndexer
	ModeMatcher
	ModeNotifier
)

// ConfMode enumerates the arguments that are acceptable "modes".
type ConfMode int

func (v *ConfMode) String() string {
	if v == nil {
		return ""
	}
	switch *v {
	case ModeCombo:
		return config.ComboMode
	case ModeIndexer:
		return config.IndexerMode
	case ModeMatcher:
		return config.MatcherMode
	case ModeNotifier:
		return config.NotifierMode
	default:
	}
	return "invalid"
}

// Get implements flag.Getter
func (v *ConfMode) Get() interface{} {
	return *v
}

// Set implements flag.Value
func (v *ConfMode) Set(s string) error {
	switch s {
	case "", "dev":
		fallthrough
	case "combo", "combination", "pizza": // "Pizza", of course, being the best Combos flavor.
		*v = ModeCombo
	case "index", "indexer":
		*v = ModeIndexer
	case "match", "matcher":
		*v = ModeMatcher
	case "notify", "notifier":
		*v = ModeNotifier
	default:
		return fmt.Errorf("unknown mode argument %q", s)
	}
	return nil
}
