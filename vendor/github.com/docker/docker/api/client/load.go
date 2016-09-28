package client

import (
	"io"
	"os"

	"golang.org/x/net/context"

	Cli "github.com/docker/docker/cli"
	"github.com/docker/docker/pkg/jsonmessage"
	flag "github.com/docker/docker/pkg/mflag"
)

// CmdLoad loads an image from a tar archive.
//
// The tar archive is read from STDIN by default, or from a tar archive file.
//
// Usage: docker load [OPTIONS]
func (cli *DockerCli) CmdLoad(args ...string) error {
	cmd := Cli.Subcmd("load", nil, Cli.DockerCommands["load"].Description, true)
	infile := cmd.String([]string{"i", "-input"}, "", "Read from a tar archive file, instead of STDIN")
	quiet := cmd.Bool([]string{"q", "-quiet"}, false, "Suppress the load output")
	cmd.Require(flag.Exact, 0)
	cmd.ParseFlags(args, true)

	var input io.Reader = cli.in
	if *infile != "" {
		file, err := os.Open(*infile)
		if err != nil {
			return err
		}
		defer file.Close()
		input = file
	}
	if !cli.isTerminalOut {
		*quiet = true
	}
	response, err := cli.client.ImageLoad(context.Background(), input, *quiet)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.JSON {
		return jsonmessage.DisplayJSONMessagesStream(response.Body, cli.out, cli.outFd, cli.isTerminalOut, nil)
	}

	_, err = io.Copy(cli.out, response.Body)
	return err
}
