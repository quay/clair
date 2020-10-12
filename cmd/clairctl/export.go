package main

import (
	"errors"
	"io"
	"os"
	"regexp"

	"github.com/quay/claircore/libvuln"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/updater"
	_ "github.com/quay/claircore/updater/defaults"
	"github.com/urfave/cli/v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// ExportCmd is the "export-updaters" subcommand.
var ExportCmd = &cli.Command{
	Name:        "export-updaters",
	Description: "Run configured exporters and export to a file.",
	Action:      exportAction,
	Usage:       "run updaters and export results",
	ArgsUsage:   "[out]",
	Flags: []cli.Flag{
		// Strict can be used to check that updaters still work.
		&cli.BoolFlag{
			Name:  "strict",
			Usage: "Return non-zero exit when updaters report errors.",
		},
		&cli.PathFlag{
			Name:      "config",
			Aliases:   []string{"c"},
			Usage:     "clair configuration file",
			Value:     "config.yaml",
			TakesFile: true,
			EnvVars:   []string{"CLAIR_CONF"},
		},
	},
}

func exportAction(c *cli.Context) error {
	ctx := c.Context
	var out io.Writer

	// Setup the output file.
	args := c.Args()
	switch args.Len() {
	case 0:
		out = os.Stdout
	case 1:
		f, err := os.Create(args.First())
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	default:
		return errors.New("too many arguments (wanted at most one)")
	}

	// Read and process the config file.
	cfg, err := loadConfig(c.String("config"))
	if err != nil {
		return err
	}
	filter, err := regexp.Compile(cfg.Updaters.Filter)
	if err != nil {
		return err
	}
	cfgs := make(map[string]driver.ConfigUnmarshaler, len(cfg.Updaters.Config))
	for name, node := range cfg.Updaters.Config {
		cfgs[name] = node.Decode
	}

	cl, _, err := cfg.Client(nil, jwt.Claims{})
	if err != nil {
		return err
	}

	u, err := libvuln.NewOfflineUpdater(cfgs, filter.MatchString, out)
	if err != nil {
		return err
	}

	defs := updater.Registered()
	cfg.Updaters.FilterSets(defs)
	if err := updater.Configure(ctx, defs, cfgs, cl); err != nil {
		return err
	}
	ufs := make([]driver.UpdaterSetFactory, 0, len(defs))
	for _, u := range defs {
		ufs = append(ufs, u)
	}

	if err := u.RunUpdaters(ctx, ufs...); err != nil {
		// Don't exit non-zero if we run into errors, unless the strict flag was
		// provided.
		code := 0
		if c.Bool("strict") {
			code = 1
		}
		return cli.Exit(err.Error(), code)
	}
	return nil
}
