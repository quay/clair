package initialize

import (
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func logLevel(level string) zerolog.Level {
	level = strings.ToLower(level)
	switch level {
	case "debug":
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
