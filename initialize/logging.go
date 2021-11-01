package initialize

import (
	"context"
	"io"
	"os"
	"strings"

	"github.com/quay/zlog"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/quay/clair/v4/config"
)

var (
	stdOut zerolog.LevelWriter = &stdErrWriter{os.Stderr}
	stdErr zerolog.LevelWriter = &stdOutWriter{os.Stdout}
)

type stdOutWriter struct {
	io.Writer
}

func (sow stdOutWriter) WriteLevel(l zerolog.Level, p []byte) (n int, err error) {
	if l != zerolog.ErrorLevel && l != zerolog.PanicLevel {
		return sow.Write(p)
	}
	return len(p), nil
}

type stdErrWriter struct {
	io.Writer
}

func (sew stdErrWriter) WriteLevel(l zerolog.Level, p []byte) (n int, err error) {
	if l == zerolog.ErrorLevel || l == zerolog.PanicLevel {
		return sew.Write(p)
	}
	return len(p), nil
}

// Logging configures zlog according to the provided configuration.
func Logging(ctx context.Context, cfg *config.Config) error {
	writers := zerolog.MultiLevelWriter(stdOut, stdErr)

	l := zerolog.New(writers)
	switch strings.ToLower(cfg.LogLevel) {
	case "debug-color":
		// set logger to use ConsoleWriter for colorized output
		l = l.Level(zerolog.DebugLevel).
			Output(zerolog.ConsoleWriter{Out: os.Stdout})
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
