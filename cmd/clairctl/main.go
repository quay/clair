package main

import (
	"context"
	"log"
	"os"

	_ "github.com/quay/claircore/updater/defaults"
	"github.com/urfave/cli/v2"
)

var (
	flagDebug bool
)

func main() {
	var exit int
	defer func() { os.Exit(exit) }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	app := &cli.App{
		Name:                 "clairctl",
		Version:              "0.1.0",
		Usage:                "interact with a clair API",
		Description:          "A command-line tool for clair v4.",
		EnableBashCompletion: true,
		Before: func(c *cli.Context) error {
			if c.IsSet("D") {
				debug.SetOutput(os.Stderr)
			}
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
		},
	}
	log.SetFlags(log.Flags())

	if err := app.RunContext(ctx, os.Args); err != nil {
		exit = 1
		if err, ok := err.(cli.ExitCoder); ok {
			exit = err.ExitCode()
		}
		log.Println(err)
	}
}
