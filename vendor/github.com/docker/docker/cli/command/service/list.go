package service

import (
	"fmt"
	"io"
	"text/tabwriter"

	distreference "github.com/docker/distribution/reference"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/cli"
	"github.com/docker/docker/cli/command"
	"github.com/docker/docker/opts"
	"github.com/docker/docker/pkg/stringid"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
)

const (
	listItemFmt = "%s\t%s\t%s\t%s\t%s\n"
)

type listOptions struct {
	quiet  bool
	filter opts.FilterOpt
}

func newListCommand(dockerCli *command.DockerCli) *cobra.Command {
	opts := listOptions{filter: opts.NewFilterOpt()}

	cmd := &cobra.Command{
		Use:     "ls [OPTIONS]",
		Aliases: []string{"list"},
		Short:   "List services",
		Args:    cli.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(dockerCli, opts)
		},
	}

	flags := cmd.Flags()
	flags.BoolVarP(&opts.quiet, "quiet", "q", false, "Only display IDs")
	flags.VarP(&opts.filter, "filter", "f", "Filter output based on conditions provided")

	return cmd
}

func runList(dockerCli *command.DockerCli, opts listOptions) error {
	ctx := context.Background()
	client := dockerCli.Client()
	out := dockerCli.Out()

	services, err := client.ServiceList(ctx, types.ServiceListOptions{Filters: opts.filter.Value()})
	if err != nil {
		return err
	}

	if len(services) > 0 && !opts.quiet {
		// only non-empty services and not quiet, should we call TaskList and NodeList api
		taskFilter := filters.NewArgs()
		for _, service := range services {
			taskFilter.Add("service", service.ID)
		}

		tasks, err := client.TaskList(ctx, types.TaskListOptions{Filters: taskFilter})
		if err != nil {
			return err
		}

		nodes, err := client.NodeList(ctx, types.NodeListOptions{})
		if err != nil {
			return err
		}

		PrintNotQuiet(out, services, nodes, tasks)
	} else if !opts.quiet {
		// no services and not quiet, print only one line with columns ID, NAME, MODE, REPLICAS...
		PrintNotQuiet(out, services, []swarm.Node{}, []swarm.Task{})
	} else {
		PrintQuiet(out, services)
	}

	return nil
}

// PrintNotQuiet shows service list in a non-quiet way.
// Besides this, command `docker stack services xxx` will call this, too.
func PrintNotQuiet(out io.Writer, services []swarm.Service, nodes []swarm.Node, tasks []swarm.Task) {
	activeNodes := make(map[string]struct{})
	for _, n := range nodes {
		if n.Status.State != swarm.NodeStateDown {
			activeNodes[n.ID] = struct{}{}
		}
	}

	running := map[string]int{}
	tasksNoShutdown := map[string]int{}

	for _, task := range tasks {
		if task.DesiredState != swarm.TaskStateShutdown {
			tasksNoShutdown[task.ServiceID]++
		}

		if _, nodeActive := activeNodes[task.NodeID]; nodeActive && task.Status.State == swarm.TaskStateRunning {
			running[task.ServiceID]++
		}
	}

	printTable(out, services, running, tasksNoShutdown)
}

func printTable(out io.Writer, services []swarm.Service, running, tasksNoShutdown map[string]int) {
	writer := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)

	// Ignore flushing errors
	defer writer.Flush()

	fmt.Fprintf(writer, listItemFmt, "ID", "NAME", "MODE", "REPLICAS", "IMAGE")

	for _, service := range services {
		mode := ""
		replicas := ""
		if service.Spec.Mode.Replicated != nil && service.Spec.Mode.Replicated.Replicas != nil {
			mode = "replicated"
			replicas = fmt.Sprintf("%d/%d", running[service.ID], *service.Spec.Mode.Replicated.Replicas)
		} else if service.Spec.Mode.Global != nil {
			mode = "global"
			replicas = fmt.Sprintf("%d/%d", running[service.ID], tasksNoShutdown[service.ID])
		}
		image := service.Spec.TaskTemplate.ContainerSpec.Image
		ref, err := distreference.ParseNamed(image)
		if err == nil {
			// update image string for display
			namedTagged, ok := ref.(distreference.NamedTagged)
			if ok {
				image = namedTagged.Name() + ":" + namedTagged.Tag()
			}
		}

		fmt.Fprintf(
			writer,
			listItemFmt,
			stringid.TruncateID(service.ID),
			service.Spec.Name,
			mode,
			replicas,
			image)
	}
}

// PrintQuiet shows service list in a quiet way.
// Besides this, command `docker stack services xxx` will call this, too.
func PrintQuiet(out io.Writer, services []swarm.Service) {
	for _, service := range services {
		fmt.Fprintln(out, service.ID)
	}
}
