package initialize

import (
	"context"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Logging will set the global logging level for Clair,
// create a global logger embedded into a CTX,
// and sets this CTX as our application's GlobalCTX.
func (i *Init) Logging() error {
	// global log level
	level := LogLevel(i.conf.LogLevel)
	zerolog.SetGlobalLevel(level)

	// attach global logger to ctx
	i.GlobalCTX, i.GlobalCancel = context.WithCancel(context.Background())
	globalLogger := log.With().Timestamp().Logger()
	i.GlobalCTX = globalLogger.WithContext(i.GlobalCTX)

	globalLogger.Info().Str("component", "init/Init.Logging").Msg("logging initialized")
	return nil
}

func LogLevel(level string) zerolog.Level {
	level = strings.ToLower(level)
	switch level {
	case "debug":
		// set global logger to use ConsoleWriter for colorized output
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
		return zerolog.DebugLevel
	case "info":
		return zerolog.InfoLevel
	case "warn":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	case "fatal":
		return zerolog.FatalLevel
	case "panic":
		return zerolog.PanicLevel
	default:
		return zerolog.InfoLevel
	}
}
