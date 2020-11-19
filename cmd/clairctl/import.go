package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/claircore/libvuln"
	"github.com/urfave/cli/v2"
)

// ImportCmd is the "import-updaters" subcommand.
var ImportCmd = &cli.Command{
	Name:      "import-updaters",
	Action:    importAction,
	Usage:     "import updates",
	ArgsUsage: "input...",
	Flags:     []cli.Flag{},
	Description: `Import updates from files or HTTP URIs.

   A configuration file is needed to run this command, see 'clairctl help'
   for how to specify one.`, // NB this has spaces, not tabs.
}

func importAction(c *cli.Context) error {
	ctx := c.Context
	// Read and process the config file.
	cfg, err := loadConfig(c.String("config"))
	if err != nil {
		return err
	}

	cl, _, err := cfg.Client(nil, commonClaim)
	if err != nil {
		return err
	}

	// Setup the input file.
	args := c.Args()
	if args.Len() != 1 {
		return errors.New("need at least one argument")
	}
	inName := args.First()

	in, err := openInput(ctx, cl, inName)
	if err != nil {
		return err
	}
	defer in.Close()

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
	f, ferr := os.Open(n)
	if ferr == nil {
		return f, nil
	}
	u, uerr := url.Parse(n)
	if uerr == nil {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
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
