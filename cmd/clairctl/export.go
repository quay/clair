package main

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/libvuln/jsonblob"
	"github.com/quay/claircore/libvuln/updates"
	_ "github.com/quay/claircore/updater/defaults"
	"github.com/urfave/cli/v2"

	"github.com/quay/clair/v4/internal/httputil"
)

// ExportCmd is the "export-updaters" subcommand.
var ExportCmd = &cli.Command{
	Name:      "export-updaters",
	Action:    exportAction,
	Usage:     "run updaters and export results",
	ArgsUsage: "[out[.gz|.zst]]",
	Flags: []cli.Flag{
		// Strict can be used to check that updaters still work.
		&cli.BoolFlag{
			Name:  "strict",
			Usage: "Return non-zero exit when updaters report errors.",
		},
		&cli.BoolFlag{
			Name:    "gzip",
			Aliases: []string{"g"},
			Usage:   "Compress output with gzip.",
		},
		&cli.BoolFlag{
			Name:    "zstd",
			Aliases: []string{"z"},
			Usage:   "Compress output with zstd.",
		},
	},
	Description: `Run configured exporters and export to a file.

If a file name is supplied and ends with ".gz" or ".zst" and neither the
"z" or "g" flag have been supplied, output will be compressed with gzip
or zstd compression, respectively.

A configuration file is needed to run this command, see 'clairctl help'
for how to specify one.`,
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
		switch {
		case c.IsSet("zstd") || c.IsSet("gzip"):
			break
		case strings.HasSuffix(args.First(), ".zst"):
			c.Set("zstd", "true")
		case strings.HasSuffix(args.First(), ".gz"):
			c.Set("gzip", "true")
		}
	default:
		return errors.New("too many arguments (wanted at most one)")
	}
	switch {
	case c.Bool("zstd"):
		enc, err := zstd.NewWriter(out)
		if err != nil {
			return err
		}
		defer func() {
			if err := enc.Close(); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		}()
		out = enc
	case c.Bool("gzip"):
		enc := gzip.NewWriter(out)
		defer func() {
			if err := enc.Close(); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		}()
		out = enc
	}

	// Read and process the config file.
	cfg, err := loadConfig(c.String("config"))
	if err != nil {
		return err
	}
	cfgs := make(map[string]driver.ConfigUnmarshaler, len(cfg.Updaters.Config))
	for name, node := range cfg.Updaters.Config {
		node := node
		cfgs[name] = func(v interface{}) error {
			b, err := json.Marshal(node)
			if err != nil {
				return err
			}
			return json.Unmarshal(b, v)
		}
	}

	cl, err := httputil.NewClient(ctx, false)
	if err != nil {
		return err
	}
	cl.Transport = httputil.RateLimiter(cl.Transport)

	store, err := jsonblob.New()
	if err != nil {
		return err
	}
	defer func() {
		if err := store.Store(out); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}()
	mgr, err := updates.NewManager(ctx, store, updates.NewLocalLockSource(), cl,
		updates.WithConfigs(cfgs),
		updates.WithEnabled(cfg.Updaters.Sets),
	)
	if err != nil {
		return err
	}

	if err := mgr.Run(ctx); err != nil {
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
