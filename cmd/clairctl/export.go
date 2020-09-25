package main

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/libvuln/jsonblob"
	"github.com/quay/claircore/libvuln/updates"
	_ "github.com/quay/claircore/updater/defaults"
	"github.com/urfave/cli/v2"
)

// ExportCmd is the "export-updaters" subcommand.
var ExportCmd = &cli.Command{
	Name:      "export-updaters",
	Action:    exportAction,
	Usage:     "run updaters and export results",
	ArgsUsage: "[out]",
	Flags: []cli.Flag{
		// Strict can be used to check that updaters still work.
		&cli.BoolFlag{
			Name:  "strict",
			Usage: "Return non-zero exit when updaters report errors.",
		},
	},
	Description: `Run configured exporters and export to a file.

   A configuration file is needed to run this command, see 'clairctl help'
   for how to specify one.`, // NB this has spaces, not tabs.
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
	cfgs := make(map[string]driver.ConfigUnmarshaler, len(cfg.Updaters.Config))
	for name, node := range cfg.Updaters.Config {
		cfgs[name] = node.Decode
	}

	cl, _, err := cfg.Client(nil, commonClaim)
	if err != nil {
		return err
	}

	// use a jsonblob store
	store, err := jsonblob.New()

	// create update manager
	mgr, err := updates.NewManager(ctx,
		store,
		nil,
		cl,
		updates.WithConfigs(cfgs),
		updates.WithEnabled(cfg.Updaters.Sets))
	if err != nil {
		return err
	}

	err = mgr.Run(ctx)
	if err != nil {
		return err
	}

	bw := bufio.NewWriter(out)
	gz := gzip.NewWriter(bw)
	defer func() {
		gz.Close()
		bw.Flush()
	}()
	if err := store.Store(gz); err != nil {
		return fmt.Errorf("failed to write jsonblob to file")
	}

	return nil
}
