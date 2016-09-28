package client

import (
	"fmt"
	"strings"

	"golang.org/x/net/context"

	Cli "github.com/docker/docker/cli"
	flag "github.com/docker/docker/pkg/mflag"
)

// CmdWait blocks until a container stops, then prints its exit code.
//
// If more than one container is specified, this will wait synchronously on each container.
//
// Usage: docker wait CONTAINER [CONTAINER...]
func (cli *DockerCli) CmdWait(args ...string) error {
	cmd := Cli.Subcmd("wait", []string{"CONTAINER [CONTAINER...]"}, Cli.DockerCommands["wait"].Description, true)
	cmd.Require(flag.Min, 1)

	cmd.ParseFlags(args, true)

	var errs []string
	for _, name := range cmd.Args() {
		status, err := cli.client.ContainerWait(context.Background(), name)
		if err != nil {
			errs = append(errs, err.Error())
		} else {
			fmt.Fprintf(cli.out, "%d\n", status)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "\n"))
	}
	return nil
}
