package idresolver

import (
	"fmt"

	"golang.org/x/net/context"

	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stringid"
)

// IDResolver provides ID to Name resolution.
type IDResolver struct {
	client    client.APIClient
	noResolve bool
	cache     map[string]string
}

// New creates a new IDResolver.
func New(client client.APIClient, noResolve bool) *IDResolver {
	return &IDResolver{
		client:    client,
		noResolve: noResolve,
		cache:     make(map[string]string),
	}
}

func (r *IDResolver) get(ctx context.Context, t interface{}, id string) (string, error) {
	switch t := t.(type) {
	case swarm.Node:
		node, _, err := r.client.NodeInspectWithRaw(ctx, id)
		if err != nil {
			return id, nil
		}
		if node.Spec.Annotations.Name != "" {
			return node.Spec.Annotations.Name, nil
		}
		if node.Description.Hostname != "" {
			return node.Description.Hostname, nil
		}
		return id, nil
	case swarm.Service:
		service, _, err := r.client.ServiceInspectWithRaw(ctx, id)
		if err != nil {
			return id, nil
		}
		return service.Spec.Annotations.Name, nil
	case swarm.Task:
		// If the caller passes the full task there's no need to do a lookup.
		if t.ID == "" {
			var err error

			t, _, err = r.client.TaskInspectWithRaw(ctx, id)
			if err != nil {
				return id, nil
			}
		}
		taskID := stringid.TruncateID(t.ID)
		if t.ServiceID == "" {
			return taskID, nil
		}
		service, err := r.Resolve(ctx, swarm.Service{}, t.ServiceID)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s.%d.%s", service, t.Slot, taskID), nil
	default:
		return "", fmt.Errorf("unsupported type")
	}

}

// Resolve will attempt to resolve an ID to a Name by querying the manager.
// Results are stored into a cache.
// If the `-n` flag is used in the command-line, resolution is disabled.
func (r *IDResolver) Resolve(ctx context.Context, t interface{}, id string) (string, error) {
	if r.noResolve {
		return id, nil
	}
	if name, ok := r.cache[id]; ok {
		return name, nil
	}
	name, err := r.get(ctx, t, id)
	if err != nil {
		return "", err
	}
	r.cache[id] = name
	return name, nil
}
