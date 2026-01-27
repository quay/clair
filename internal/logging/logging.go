// Package logging holds the logging singletons for Clair.
//
// An init function sets the [slog] default Logger.
package logging

import (
	"log/slog"
	"os"

	"github.com/quay/claircore/toolkit/log"
	"github.com/quay/zlog/v2"
)

func init() {
	slog.SetLogLoggerLevel(slog.LevelDebug)
	SetLogger(DefaultOptions())
}

// Level is the [slog.Leveler] that the [zlog.Options] returned by
// [DefaultOptions] points to.
var Level slog.LevelVar

// DefaultOptions returns a default set of options for a zlog/v2 [slog.Handler].
func DefaultOptions() *zlog.Options {
	return &zlog.Options{
		Level:      &Level,
		ContextKey: log.AttrsKey,
		LevelKey:   log.LevelKey,
	}
}

// SetLogger configures the default [slog.Logger] to use a zlog-backed
// [slog.Handler] writing to [os.Stderr] using the passed [zlog.Options].
func SetLogger(opts *zlog.Options) {
	slog.SetDefault(slog.New(zlog.NewHandler(os.Stderr, opts)))
}
