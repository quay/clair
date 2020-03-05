package initialize

import (
	"context"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Logging will set the global logging level for Clair,
// attach a Logger for all other Init methods to use,
// and embeds a logger into a globalCTX.
//
// This globalCTX will be provided to all long running routines
func (i *Init) Logging() error {
	// global log level
	level := logLevel(i.conf.LogLevel)
	zerolog.SetGlobalLevel(level)

	// global ctx
	i.GlobalCTX, i.GlobalCancel = context.WithCancel(context.Background())
	globalLogger := log.With().Str("version", Version).Logger()
	i.GlobalCTX = globalLogger.WithContext(i.GlobalCTX)

	globalLogger.Info().Str("component", "init/Init.Logging").Msg("logging initialized")
	return nil
}
