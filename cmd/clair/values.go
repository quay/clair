package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Mode defines the operation modes Clair may run in.
type Mode string

const (
	IndexerMode Mode = "indexer"
	MatcherMode Mode = "matcher"
)

// ModeValue implements the flag.Value interface.
//
// ModeValue parses a correct mode from the cli args or returns an error.
type ModeValue struct {
	Mode Mode
}

func (v ModeValue) String() string {
	return string(v.Mode)
}
func (v ModeValue) Set(s string) error {
	s = strings.ToLower(s)
	switch s {
	case string(IndexerMode):
		v.Mode = IndexerMode
		return nil
	case string(MatcherMode):
		v.Mode = MatcherMode
		return nil
	default:
		return fmt.Errorf("undefined mode %s. expected 'indexer' or 'matcher'", s)
	}
}

// ConfValue implements the flag.Value interface
//
// ConfValue parses a filesystem path and confirms it exists and is readable.
// If these conditions do not pass a error is returned.
type ConfValue struct {
	file *os.File
}

func (v ConfValue) String() string {
	if v.file == nil {
		return ""
	}
	return v.file.Name()
}

func (v ConfValue) Set(s string) error {
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
