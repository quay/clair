package initialize

import (
	"context"
	"fmt"
	"os"

	"github.com/quay/clair/config"
	"github.com/quay/zlog"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Logging configures zlog according to the provided configuration.
func Logging(ctx context.Context, cfg *config.Config) error {
	l := zerolog.New(os.Stderr)
	switch cfg.LogLevel {
	case config.DebugColorLog:
		// set logger to use ConsoleWriter for colorized output
		l = l.Level(zerolog.DebugLevel).
			Output(zerolog.ConsoleWriter{Out: os.Stderr})
	case config.DebugLog:
		l = l.Level(zerolog.DebugLevel)
	case config.InfoLog:
		l = l.Level(zerolog.InfoLevel)
	case config.WarnLog:
		l = l.Level(zerolog.WarnLevel)
	case config.ErrorLog:
		l = l.Level(zerolog.ErrorLevel)
	case config.FatalLog:
		l = l.Level(zerolog.FatalLevel)
	case config.PanicLog:
		l = l.Level(zerolog.PanicLevel)
	default:
		return fmt.Errorf("unknown log level: %v", cfg.LogLevel)
	}
	l = l.With().
		Timestamp().
		Logger()
	zlog.Set(&l)
	log.Logger = zerolog.Nop()
	zlog.Debug(ctx).Str("component", "initialize/Logging").Msg("logging initialized")
	return nil
}
