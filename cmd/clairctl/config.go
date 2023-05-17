package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/quay/zlog"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"
)

var CheckConfigCmd = &cli.Command{
	Name:  "check-config",
	Usage: "print a fully-resolved clair config",
	Description: `Check-config can be used to check that drop-in config files are being merged correctly.

The output is not currently suitable to be fed back into Clair.`,
	Action:    checkConfigAction,
	ArgsUsage: "FILE[...]",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "out",
			Aliases: []string{"o"},
			Usage:   "output format: json, yaml",
			Value:   "json",
		},
	},
}

func checkConfigAction(c *cli.Context) error {
	done := make(map[string]struct{})
	todo := c.Args().Slice()
	ctx := c.Context
	var enc interface {
		Encode(any) error
	}
	if len(todo) == 0 {
		return errors.New("missing needed arguments")
	}
Again:
	switch v := c.String("out"); v {
	case "json":
		j := json.NewEncoder(os.Stdout)
		j.SetIndent("", "\t")
		enc = j
	case "yaml":
		zlog.Warn(ctx).Msg("some values do no round-trip the yaml encoder correctly -- make sure to consult the documentation")
		y := yaml.NewEncoder(os.Stdout)
		y.SetIndent(2)
		enc = y
	default:
		zlog.Info(ctx).Str("out", v).Msg("unknown 'out' kind, using 'json'")
		c.Set("out", "json")
		goto Again
	}
	for _, f := range todo {
		if _, ok := done[f]; ok {
			continue
		}
		done[f] = struct{}{}
		if len(todo) > 1 {
			fmt.Println("#", f)
		}
		cfg, err := loadConfig(f)
		if err != nil {
			return err
		}
		if err := enc.Encode(cfg); err != nil {
			return err
		}
	}
	return nil
}
