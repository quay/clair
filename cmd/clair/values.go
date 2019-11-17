package main

import (
	"fmt"
	"os"
	"path/filepath"
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
