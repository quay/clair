package initialize

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/quay/clair/config"

	"github.com/quay/clair/v4/internal/logging"
)

// Logging configures slog according to the provided configuration.
func Logging(ctx context.Context, cfg *config.Config) error {
	switch cfg.LogLevel {
	case config.DebugColorLog:
		opts := logging.DefaultOptions()
		opts.ProseFormat = true
		logging.SetLogger(opts)
		fallthrough
	case config.DebugLog:
		logging.Level.Set(slog.LevelDebug)
	case config.InfoLog:
		logging.Level.Set(slog.LevelInfo)
	case config.WarnLog:
		logging.Level.Set(slog.LevelWarn)
	case config.ErrorLog:
		logging.Level.Set(slog.LevelError)
	case config.FatalLog:
		logging.Level.Set(slog.LevelError + 4)
	case config.PanicLog:
		logging.Level.Set(slog.LevelError + 8)
	default:
		return fmt.Errorf("unknown log level: %v", cfg.LogLevel)
	}

	slog.DebugContext(ctx, "logging configured")
	return nil
}
