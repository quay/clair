package container

import (
	"fmt"
	"io"
	"os"

	"github.com/docker/distribution/reference"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	networktypes "github.com/docker/docker/api/types/network"
	"github.com/docker/docker/cli"
	"github.com/docker/docker/cli/command"
	"github.com/docker/docker/cli/command/image"
	apiclient "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/docker/docker/registry"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/net/context"
)

type createOptions struct {
	name string
}

// NewCreateCommand creates a new cobra.Command for `docker create`
func NewCreateCommand(dockerCli *command.DockerCli) *cobra.Command {
	var opts createOptions
	var copts *containerOptions

	cmd := &cobra.Command{
		Use:   "create [OPTIONS] IMAGE [COMMAND] [ARG...]",
		Short: "Create a new container",
		Args:  cli.RequiresMinArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			copts.Image = args[0]
			if len(args) > 1 {
				copts.Args = args[1:]
			}
			return runCreate(dockerCli, cmd.Flags(), &opts, copts)
		},
	}

	flags := cmd.Flags()
	flags.SetInterspersed(false)

	flags.StringVar(&opts.name, "name", "", "Assign a name to the container")

	// Add an explicit help that doesn't have a `-h` to prevent the conflict
	// with hostname
	flags.Bool("help", false, "Print usage")

	command.AddTrustVerificationFlags(flags)
	copts = addFlags(flags)
	return cmd
}

func runCreate(dockerCli *command.DockerCli, flags *pflag.FlagSet, opts *createOptions, copts *containerOptions) error {
	config, hostConfig, networkingConfig, err := parse(flags, copts)
	if err != nil {
		reportError(dockerCli.Err(), "create", err.Error(), true)
		return cli.StatusError{StatusCode: 125}
	}
	response, err := createContainer(context.Background(), dockerCli, config, hostConfig, networkingConfig, hostConfig.ContainerIDFile, opts.name)
	if err != nil {
		return err
	}
	fmt.Fprintln(dockerCli.Out(), response.ID)
	return nil
}

func pullImage(ctx context.Context, dockerCli *command.DockerCli, image string, out io.Writer) error {
	ref, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return err
	}

	// Resolve the Repository name from fqn to RepositoryInfo
	repoInfo, err := registry.ParseRepositoryInfo(ref)
	if err != nil {
		return err
	}

	authConfig := command.ResolveAuthConfig(ctx, dockerCli, repoInfo.Index)
	encodedAuth, err := command.EncodeAuthToBase64(authConfig)
	if err != nil {
		return err
	}

	options := types.ImageCreateOptions{
		RegistryAuth: encodedAuth,
	}

	responseBody, err := dockerCli.Client().ImageCreate(ctx, image, options)
	if err != nil {
		return err
	}
	defer responseBody.Close()

	return jsonmessage.DisplayJSONMessagesStream(
		responseBody,
		out,
		dockerCli.Out().FD(),
		dockerCli.Out().IsTerminal(),
		nil)
}

type cidFile struct {
	path    string
	file    *os.File
	written bool
}

func (cid *cidFile) Close() error {
	cid.file.Close()

	if cid.written {
		return nil
	}
	if err := os.Remove(cid.path); err != nil {
		return fmt.Errorf("failed to remove the CID file '%s': %s \n", cid.path, err)
	}

	return nil
}

func (cid *cidFile) Write(id string) error {
	if _, err := cid.file.Write([]byte(id)); err != nil {
		return fmt.Errorf("Failed to write the container ID to the file: %s", err)
	}
	cid.written = true
	return nil
}

func newCIDFile(path string) (*cidFile, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("Container ID file found, make sure the other container isn't running or delete %s", path)
	}

	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("Failed to create the container ID file: %s", err)
	}

	return &cidFile{path: path, file: f}, nil
}

func createContainer(ctx context.Context, dockerCli *command.DockerCli, config *container.Config, hostConfig *container.HostConfig, networkingConfig *networktypes.NetworkingConfig, cidfile, name string) (*container.ContainerCreateCreatedBody, error) {
	stderr := dockerCli.Err()

	var (
		containerIDFile *cidFile
		trustedRef      reference.Canonical
		namedRef        reference.Named
	)

	if cidfile != "" {
		var err error
		if containerIDFile, err = newCIDFile(cidfile); err != nil {
			return nil, err
		}
		defer containerIDFile.Close()
	}

	ref, err := reference.ParseAnyReference(config.Image)
	if err != nil {
		return nil, err
	}
	if named, ok := ref.(reference.Named); ok {
		if reference.IsNameOnly(named) {
			namedRef = reference.EnsureTagged(named)
		} else {
			namedRef = named
		}

		if taggedRef, ok := namedRef.(reference.NamedTagged); ok && command.IsTrusted() {
			var err error
			trustedRef, err = image.TrustedReference(ctx, dockerCli, taggedRef, nil)
			if err != nil {
				return nil, err
			}
			config.Image = reference.FamiliarString(trustedRef)
		}
	}

	//create the container
	response, err := dockerCli.Client().ContainerCreate(ctx, config, hostConfig, networkingConfig, name)

	//if image not found try to pull it
	if err != nil {
		if apiclient.IsErrImageNotFound(err) && namedRef != nil {
			fmt.Fprintf(stderr, "Unable to find image '%s' locally\n", reference.FamiliarString(namedRef))

			// we don't want to write to stdout anything apart from container.ID
			if err = pullImage(ctx, dockerCli, config.Image, stderr); err != nil {
				return nil, err
			}
			if taggedRef, ok := namedRef.(reference.NamedTagged); ok && trustedRef != nil {
				if err := image.TagTrusted(ctx, dockerCli, trustedRef, taggedRef); err != nil {
					return nil, err
				}
			}
			// Retry
			var retryErr error
			response, retryErr = dockerCli.Client().ContainerCreate(ctx, config, hostConfig, networkingConfig, name)
			if retryErr != nil {
				return nil, retryErr
			}
		} else {
			return nil, err
		}
	}

	for _, warning := range response.Warnings {
		fmt.Fprintf(stderr, "WARNING: %s\n", warning)
	}
	if containerIDFile != nil {
		if err = containerIDFile.Write(response.ID); err != nil {
			return nil, err
		}
	}
	return &response, nil
}
