package client

import (
	"fmt"
	"strings"

	Cli "github.com/docker/docker/cli"
	flag "github.com/docker/docker/pkg/mflag"
	"github.com/docker/go-connections/nat"
)

// CmdPort lists port mappings for a container.
// If a private port is specified, it also shows the public-facing port that is NATed to the private port.
//
// Usage: docker port CONTAINER [PRIVATE_PORT[/PROTO]]
func (cli *DockerCli) CmdPort(args ...string) error {
	cmd := Cli.Subcmd("port", []string{"CONTAINER [PRIVATE_PORT[/PROTO]]"}, Cli.DockerCommands["port"].Description, true)
	cmd.Require(flag.Min, 1)

	cmd.ParseFlags(args, true)

	c, err := cli.client.ContainerInspect(cmd.Arg(0))
	if err != nil {
		return err
	}

	if cmd.NArg() == 2 {
		var (
			port  = cmd.Arg(1)
			proto = "tcp"
			parts = strings.SplitN(port, "/", 2)
		)

		if len(parts) == 2 && len(parts[1]) != 0 {
			port = parts[0]
			proto = parts[1]
		}
		natPort := port + "/" + proto
		newP, err := nat.NewPort(proto, port)
		if err != nil {
			return err
		}
		if frontends, exists := c.NetworkSettings.Ports[newP]; exists && frontends != nil {
			for _, frontend := range frontends {
				fmt.Fprintf(cli.out, "%s:%s\n", frontend.HostIP, frontend.HostPort)
			}
			return nil
		}
		return fmt.Errorf("Error: No public port '%s' published for %s", natPort, cmd.Arg(0))
	}

	for from, frontends := range c.NetworkSettings.Ports {
		for _, frontend := range frontends {
			fmt.Fprintf(cli.out, "%s -> %s:%s\n", from, frontend.HostIP, frontend.HostPort)
		}
	}

	return nil
}
