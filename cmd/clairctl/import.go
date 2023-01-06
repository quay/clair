package main

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/klauspost/compress/zstd"
	"github.com/quay/claircore/libvuln"
	"github.com/urfave/cli/v2"

	"github.com/quay/clair/v4/internal/httputil"
)

// ImportCmd is the "import-updaters" subcommand.
var ImportCmd = &cli.Command{
	Name:      "import-updaters",
	Action:    importAction,
	Usage:     "import updates",
	ArgsUsage: "input[.gz|.zst]|-",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "gzip",
			Aliases: []string{"g"},
			Usage:   "Decompress input with gzip.",
		},
		&cli.BoolFlag{
			Name:    "zstd",
			Aliases: []string{"z"},
			Usage:   "Decompress input with zstd.",
		},
	},
	Description: `Import updates from a file or HTTP URI.

If the supplied file name ends with ".gz" or ".zst" and neither the "z"
or "g" flag have been supplied, input will be decompressed with gzip or
zstd compression, respectively.

A configuration file is needed to run this command, see 'clairctl help'
for how to specify one.`,
}

func importAction(c *cli.Context) error {
	ctx := c.Context
	// Read and process the config file.
	cfg, err := loadConfig(c.String("config"))
	if err != nil {
		return err
	}

	cl, err := httputil.NewClient(ctx, false)
	if err != nil {
		return err
	}

	// Setup the input file.
	args := c.Args()
	if args.Len() != 1 {
		return errors.New("need one argument")
	}
	inName := args.First()
	switch {
	case c.IsSet("zstd") || c.IsSet("gzip"):
		break
	case strings.HasSuffix(inName, ".zst"):
		c.Set("zstd", "true")
	case strings.HasSuffix(inName, ".gz"):
		c.Set("gzip", "true")
	}

	in, err := openInput(ctx, cl, inName)
	if err != nil {
		return err
	}
	defer in.Close()
	switch {
	case c.Bool("zstd"):
		dec, err := zstd.NewReader(in)
		if err != nil {
			return err
		}
		defer dec.Close()
		in = io.NopCloser(dec)
	case c.Bool("gzip"):
		dec, err := gzip.NewReader(in)
		if err != nil {
			return err
		}
		defer func() {
			if err := dec.Close(); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		}()
		in = dec
	}

	pool, err := pgxpool.Connect(ctx, cfg.Matcher.ConnString)
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := libvuln.OfflineImport(ctx, pool, in); err != nil {
		return err
	}
	return nil
}

func openInput(ctx context.Context, c *http.Client, n string) (io.ReadCloser, error) {
	if n == "-" {
		return os.Stdin, nil
	}
	f, ferr := os.Open(n)
	if ferr == nil {
		return f, nil
	}
	u, uerr := url.Parse(n)
	if uerr == nil {
		req, err := httputil.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		res, err := c.Do(req)
		if err != nil {
			if res != nil {
				res.Body.Close()
			}
			return nil, err
		}
		if res.StatusCode != http.StatusOK {
			res.Body.Close()
			return nil, fmt.Errorf("unexpected response: %d %s", res.StatusCode, res.Status)
		}
		return res.Body, nil
	}
	return nil, fmt.Errorf("error opening input:\n\t%v\n\t%v", ferr, uerr)
}
