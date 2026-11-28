package config

import (
	"fmt"
	"strings"
)

//go:generate -command stringer go run golang.org/x/tools/cmd/stringer@v0.8.0
//go:generate stringer -type Mode,LogLevel -linecomment -output enums_string.go

// A Mode is an operating mode recognized by Clair.
//
// This is not directly settable by serializing into a Config object.
type Mode int

// Clair modes, with their string representations as the comments.
const (
	ComboMode    Mode = iota // combo
	IndexerMode              // indexer
	MatcherMode              // matcher
	NotifierMode             // notifier
)

// ParseMode returns a mode for the given string.
//
// The passed string is case-insensitive.
func ParseMode(s string) (Mode, error) {
	for i, lim := 0, len(_Mode_index); i < lim; i++ {
		m := Mode(i)
		if strings.EqualFold(s, m.String()) {
			return m, nil
		}
	}
	return Mode(-1), fmt.Errorf(`unknown mode %q`, s)
}
