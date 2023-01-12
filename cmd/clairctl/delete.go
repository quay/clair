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
	ctx := c.Context
	hc, err := httputil.NewClient(ctx, false)
	if err != nil {
		return err
	}

	var s *httputil.Signer
	if useCfg {
		cfg, err := loadConfig(c.Path("config"))
		if err != nil {
			return err
		}
		s, err = httputil.NewSigner(ctx, cfg, commonClaim)
		if err != nil {
			return err
		}
		if err = s.Add(ctx, c.String("host")); err != nil {
			return err
		}

	}
	cc, err := NewClient(hc, c.String("host"), s)
	if err != nil {
		return err
	}
	err = cc.DeleteIndexReports(c.Context, ds)
	if err != nil {
		return err
	}
	return nil
}
