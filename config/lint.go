package config

import (
	"errors"
	"strings"
)

// Lint runs lints on the provided Config.
//
// An error is reported only if an error occurred while running the lints. An
// invalid Config may still report a nil error along with a slice of Warnings.
//
// Most validation steps run by Validate will also run lints.
func Lint(c *Config) ([]Warning, error) {
	return forEach(c, func(i interface{}) ([]Warning, error) {
		if l, ok := i.(linter); ok {
			return l.lint()
		}
		return nil, nil
	})
}

// Types in this package can implement this interface to report common issues or
// deprecation warnings.
type linter interface {
	lint() ([]Warning, error)
}

// Warning is a linter warning.
//
// Users can treat them like errors and use the sentinel values exported by this
// package.
type Warning struct {
	// Should have "inner" XOR "msg" populated.
	inner error
	msg   string
	path  string // json-schema style path
}

// AppendText implements [encoding.TextAppender].
func (w Warning) AppendText(b []byte) ([]byte, error) {
	if w.inner != nil {
		b = append(b, w.inner.Error()...)
	} else {
		b = append(b, w.msg...)
	}
	b = append(b, " (at "...)
	b = append(b, w.path...)
	b = append(b, ')')
	return b, nil
}

// MarshalText implements [encoding.TextMarshaler].
//
// Prefer using [Warning.AppendText].
func (w Warning) MarshalText() ([]byte, error) {
	return w.AppendText(nil)
}

func (w *Warning) Error() string {
	var b strings.Builder
	if w.inner != nil {
		b.WriteString(w.inner.Error())
	} else {
		b.WriteString(w.msg)
	}
	b.WriteString(" (at ")
	b.WriteString(w.path)
	b.WriteRune(')')
	return b.String()
}

func (w *Warning) Unwrap() error { return w.inner }

// These are some common kinds of Warnings.
var (
	ErrDeprecated = errors.New("setting will be removed in a future release")
)
