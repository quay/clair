package plugin

import (
	"github.com/docker/docker/cli"
	"github.com/docker/docker/cli/command"
	"github.com/docker/docker/cli/command/formatter"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
)

type listOptions struct {
	quiet   bool
	noTrunc bool
	format  string
}

func newListCommand(dockerCli *command.DockerCli) *cobra.Command {
	var opts listOptions

	cmd := &cobra.Command{
		Use:     "ls [OPTIONS]",
		Short:   "List plugins",
		Aliases: []string{"list"},
		Args:    cli.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(dockerCli, opts)
		},
	}

	flags := cmd.Flags()

	flags.BoolVarP(&opts.quiet, "quiet", "q", false, "Only display plugin IDs")
	flags.BoolVar(&opts.noTrunc, "no-trunc", false, "Don't truncate output")
	flags.StringVar(&opts.format, "format", "", "Pretty-print plugins using a Go template")

	return cmd
}

func runList(dockerCli *command.DockerCli, opts listOptions) error {
	plugins, err := dockerCli.Client().PluginList(context.Background())
	if err != nil {
		return err
	}

	format := opts.format
	if len(format) == 0 {
		if len(dockerCli.ConfigFile().PluginsFormat) > 0 && !opts.quiet {
			format = dockerCli.ConfigFile().PluginsFormat
		} else {
			format = formatter.TableFormatKey
		}
	}

	pluginsCtx := formatter.Context{
		Output: dockerCli.Out(),
		Format: formatter.NewPluginFormat(format, opts.quiet),
		Trunc:  !opts.noTrunc,
	}
	return formatter.PluginWrite(pluginsCtx, plugins)
}
