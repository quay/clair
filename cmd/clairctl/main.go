package main

import (
	"context"
	"os"
	"time"

	_ "github.com/quay/claircore/updater/defaults"
	"github.com/quay/zlog"
	"github.com/rs/zerolog"
	"github.com/urfave/cli/v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	logout = zerolog.New(&zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
	}).Level(zerolog.InfoLevel).
		With().
		Timestamp().
		Logger()

	commonClaim = jwt.Claims{}
)

func main() {
	var exit int
	defer func() { os.Exit(exit) }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	app := &cli.App{
		Name:                 "clairctl",
		Version:              "0.2.0",
		Usage:                "interact with a clair API",
		Description:          "A command-line tool for clair v4.",
		EnableBashCompletion: true,
		Before: func(c *cli.Context) error {
			if c.IsSet("q") {
				logout = logout.Level(zerolog.WarnLevel)
			}
			if c.IsSet("D") {
				logout = logout.Level(zerolog.DebugLevel)
			}
			zlog.Set(&logout)
			commonClaim.Issuer = c.String("issuer")
			return nil
		},
		Commands: []*cli.Command{
			ManifestCmd,
			ReportCmd,
			ExportCmd,
			ImportCmd,
		},
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "D",
				Usage: "print debugging logs",
			},
			&cli.BoolFlag{
				Name:  "q",
				Usage: "quieter log output",
			},
			&cli.PathFlag{
				Name:      "config",
				Aliases:   []string{"c"},
				Usage:     "clair configuration file",
				Value:     "config.yaml",
				TakesFile: true,
				EnvVars:   []string{"CLAIR_CONF"},
			},
			&cli.StringFlag{
				Name:    "issuer",
				Aliases: []string{"iss"},
				Usage:   `jwt "issuer" to use when making authenticated requests`,
				Value:   "clairctl",
			},
		},
		ExitErrHandler: func(c *cli.Context, err error) {
			if err != nil {
				exit = 1
				if err, ok := err.(cli.ExitCoder); ok {
					exit = err.ExitCode()
				}
				logout.Error().Err(err).Send()
			}
		},
	}

	app.RunContext(ctx, os.Args)
}
