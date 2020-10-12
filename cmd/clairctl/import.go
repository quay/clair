package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/claircore/libvuln"
	"github.com/urfave/cli/v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// ImportCmd is the "import-updaters" subcommand.
var ImportCmd = &cli.Command{
	Name:        "import-updaters",
	Description: "Import updates from a file.",
	Action:      importAction,
	Usage:       "import updates",
	ArgsUsage:   "in",
	Flags: []cli.Flag{
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

func importAction(c *cli.Context) error {
	ctx := c.Context
	// Read and process the config file.
	cfg, err := loadConfig(c.String("config"))
	if err != nil {
		return err
	}

	cl, _, err := cfg.Client(nil, jwt.Claims{})
	if err != nil {
		return err
	}

	// Setup the input file.
	args := c.Args()
	if args.Len() != 1 {
		return errors.New("need at least one argument")
	}
	inName := args.First()

	var in io.Reader
	u, uerr := url.Parse(inName)
	f, ferr := os.Open(inName)
	if f != nil {
		defer f.Close()
	}
	switch {
	case uerr == nil:
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return err
		}
		res, err := cl.Do(req)
		if res != nil {
			defer res.Body.Close()
		}
		if err != nil {
			return err
		}
		if res.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected response: %d %s", res.StatusCode, res.Status)
		}
		in = res.Body
	case ferr == nil:
		in = f
	default:
		return fmt.Errorf("unable to make sense of argument %q", inName)
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
