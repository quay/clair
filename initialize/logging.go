package initialize

import (
	"context"
	"os"
	"strings"

	"github.com/quay/clair/config"
	"github.com/quay/zlog"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Logging configures zlog according to the provided configuration.
func Logging(ctx context.Context, cfg *config.Config) error {
	l := zerolog.New(os.Stderr)
	switch strings.ToLower(cfg.LogLevel) {
	case "debug-color":
		// set logger to use ConsoleWriter for colorized output
		l = l.Level(zerolog.DebugLevel).
			Output(zerolog.ConsoleWriter{Out: os.Stderr})
	case "debug":
		l = l.Level(zerolog.DebugLevel)
	case "info":
		l = l.Level(zerolog.InfoLevel)
	case "warn":
		l = l.Level(zerolog.WarnLevel)
	case "error":
		l = l.Level(zerolog.ErrorLevel)
	case "fatal":
		l = l.Level(zerolog.FatalLevel)
	case "panic":
		l = l.Level(zerolog.PanicLevel)
	default:
		l = l.Level(zerolog.InfoLevel)
	}
	l = l.With().
		Timestamp().
		Logger()
	zlog.Set(&l)
	log.Logger = zerolog.Nop()
	l.Debug().Str("component", "initialize/Logging").Msg("logging initialized")
	return nil
}
