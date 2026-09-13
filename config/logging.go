package config

import (
	"encoding"
	"errors"
	"fmt"
	"strings"
)

// Logging is all the log configuration.
type Logging struct {
	Level          LogLevel `yaml:"level,omitempty" json:"level,omitempty"`
	OmitTimestamps bool     `yaml:"omit_timestamps,omitempty" json:"omit_timestamps,omitempty"`
	Prose          bool     `yaml:"prose,omitempty" json:"prose,omitempty"`
}

// A LogLevel is a log level recognized by Clair.
//
// The zero value is [InfoLog].
type LogLevel int

// The recognized log levels, with their string representations as the comments.
//
// Note [FatalLog] and [PanicLog] are not used in Clair or Claircore, and will
// result in almost no logging.
const (
	TraceLog LogLevel = iota - 3 // trace
	// Deprecated: Use the "Prose" toggle to request a non-JSON output format.
	DebugColorLog // debug-color
	DebugLog      // debug
	InfoLog       // info
	WarnLog       // warn
	ErrorLog      // error
	FatalLog      // fatal
	PanicLog      // panic
)

// Assert that the zero value is correct:
var _ = [1]struct{}{{}}[InfoLog]

// ParseLogLevel returns the log level for the given string.
//
// The passed string is case-insensitive.
func ParseLogLevel(s string) (LogLevel, error) {
	const offset = int(TraceLog)
	for i, lim := 0, len(_LogLevel_index); i < lim; i++ {
		l := LogLevel(i + offset)
		if strings.EqualFold(s, l.String()) {
			return l, nil
		}
	}
	return LogLevel(-127), fmt.Errorf(`unknown log level %q`, s)
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (l *LogLevel) UnmarshalText(b []byte) (err error) {
	*l, err = ParseLogLevel(string(b))
	if err != nil {
		return err
	}
	return nil
}

// MarshalText implements [encoding.TextMarshaler].
func (l *LogLevel) MarshalText() ([]byte, error) {
	const offset = int(TraceLog)
	if l == nil {
		return nil, errors.New("invalid LogLevel pointer: <nil>")
	}
	i := int(*l) - offset
	// We never re-serialize the "debug-color" level, because it's an annoying
	// wart.
	if *l == DebugColorLog {
		i++
	}
	if i < 0 || i >= len(_LogLevel_index)-1 {
		return nil, fmt.Errorf("invalid LogLevel: %q", l.String())
	}
	return []byte(_LogLevel_name[_LogLevel_index[i]:_LogLevel_index[i+1]]), nil
}

// Assert LogLevel implements everything that's needed.
var (
	_ encoding.TextUnmarshaler = (*LogLevel)(nil)
	_ encoding.TextMarshaler   = (*LogLevel)(nil)
)

func (l *Logging) validate(mode Mode) ([]Warning, error) {
	ws, err := l.lint()
	if err != nil {
		return ws, err
	}
	if l.Level == DebugColorLog {
		l.Level++
		l.Prose = true
	}
	return ws, nil
}

func (l *Logging) lint() (ws []Warning, _ error) {
	if l.Level > ErrorLog {
		ws = append(ws, Warning{
			path: ".level",
			msg:  `"fatal" and "panic" levels are not used and will result in almost no logging`,
		})
	}
	if l.Level == DebugColorLog {
		ws = append(ws, Warning{
			path: ".level",
			msg:  `"debug-color" is deprecated; use "debug" and set the "prose" option`,
		})
	}
	return ws, nil
}
