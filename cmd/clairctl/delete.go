package main

import (
	"errors"
	"os"

	"github.com/quay/claircore"
	"github.com/urfave/cli/v2"

	"github.com/quay/clair/v4/internal/httputil"
)

var DeleteCmd = &cli.Command{
	Name:        "delete",
	Description: "Delete index reports for given manifest digests.",
	Action:      deleteAction,
	Usage:       "deletes index reports for given manifest digests",
	ArgsUsage:   "digest...",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "host",
			Usage:   "URL for the clairv4 v1 API.",
			Value:   "http://localhost:6060/",
			EnvVars: []string{"CLAIR_API"},
		},
	},
}

func deleteAction(c *cli.Context) error {
	args := c.Args()
	if args.Len() == 0 {
		return errors.New("missing needed arguments")
	}
	ds := []claircore.Digest{}
	for i := 0; i < args.Len(); i++ {
		d, err := claircore.ParseDigest(args.Get(i))
		if err != nil {
			return err
		}
		ds = append(ds, d)
	}

	fi, err := os.Stat(c.Path("config"))
	useCfg := err == nil && !fi.IsDir()

	var cc *Client
	if useCfg {
		cfg, e := loadConfig(c.Path("config"))
		if e != nil {
			return e
		}
		hc, _, e := httputil.Client(nil, &commonClaim, cfg)
		if e != nil {
			return e
		}
		cc, err = NewClient(hc, c.String("host"))
	} else {
		cc, err = NewClient(nil, c.String("host"))
	}
	if err != nil {
		return err
	}
	err = cc.DeleteIndexReports(c.Context, ds)
	if err != nil {
		return err
	}
	return nil
}
