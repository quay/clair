package client

import (
	"github.com/docker/docker/api/client/formatter"
	Cli "github.com/docker/docker/cli"
	"github.com/docker/docker/opts"
	flag "github.com/docker/docker/pkg/mflag"
	"github.com/docker/engine-api/types"
	"github.com/docker/engine-api/types/filters"
)

// CmdPs outputs a list of Docker containers.
//
// Usage: docker ps [OPTIONS]
func (cli *DockerCli) CmdPs(args ...string) error {
	var (
		err error

		psFilterArgs = filters.NewArgs()

		cmd      = Cli.Subcmd("ps", nil, Cli.DockerCommands["ps"].Description, true)
		quiet    = cmd.Bool([]string{"q", "-quiet"}, false, "Only display numeric IDs")
		size     = cmd.Bool([]string{"s", "-size"}, false, "Display total file sizes")
		all      = cmd.Bool([]string{"a", "-all"}, false, "Show all containers (default shows just running)")
		noTrunc  = cmd.Bool([]string{"-no-trunc"}, false, "Don't truncate output")
		nLatest  = cmd.Bool([]string{"l", "-latest"}, false, "Show the latest created container (includes all states)")
		since    = cmd.String([]string{"#-since"}, "", "Show containers created since Id or Name (includes all states)")
		before   = cmd.String([]string{"#-before"}, "", "Only show containers created before Id or Name")
		last     = cmd.Int([]string{"n"}, -1, "Show n last created containers (includes all states)")
		format   = cmd.String([]string{"-format"}, "", "Pretty-print containers using a Go template")
		flFilter = opts.NewListOpts(nil)
	)
	cmd.Require(flag.Exact, 0)

	cmd.Var(&flFilter, []string{"f", "-filter"}, "Filter output based on conditions provided")

	cmd.ParseFlags(args, true)
	if *last == -1 && *nLatest {
		*last = 1
	}

	// Consolidate all filter flags, and sanity check them.
	// They'll get processed in the daemon/server.
	for _, f := range flFilter.GetAll() {
		if psFilterArgs, err = filters.ParseFlag(f, psFilterArgs); err != nil {
			return err
		}
	}

	options := types.ContainerListOptions{
		All:    *all,
		Limit:  *last,
		Since:  *since,
		Before: *before,
		Size:   *size,
		Filter: psFilterArgs,
	}

	containers, err := cli.client.ContainerList(options)
	if err != nil {
		return err
	}

	f := *format
	if len(f) == 0 {
		if len(cli.PsFormat()) > 0 && !*quiet {
			f = cli.PsFormat()
		} else {
			f = "table"
		}
	}

	psCtx := formatter.ContainerContext{
		Context: formatter.Context{
			Output: cli.out,
			Format: f,
			Quiet:  *quiet,
			Trunc:  !*noTrunc,
		},
		Size:       *size,
		Containers: containers,
	}

	psCtx.Write()

	return nil
}
