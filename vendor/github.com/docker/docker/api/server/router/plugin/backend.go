package plugin

import (
	"io"
	"net/http"

	enginetypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/reference"
	"golang.org/x/net/context"
)

// Backend for Plugin
type Backend interface {
	Disable(name string, config *enginetypes.PluginDisableConfig) error
	Enable(name string, config *enginetypes.PluginEnableConfig) error
	List() ([]enginetypes.Plugin, error)
	Inspect(name string) (*enginetypes.Plugin, error)
	Remove(name string, config *enginetypes.PluginRmConfig) error
	Set(name string, args []string) error
	Privileges(ctx context.Context, ref reference.Named, metaHeaders http.Header, authConfig *enginetypes.AuthConfig) (enginetypes.PluginPrivileges, error)
	Pull(ctx context.Context, ref reference.Named, name string, metaHeaders http.Header, authConfig *enginetypes.AuthConfig, privileges enginetypes.PluginPrivileges, outStream io.Writer) error
	Push(ctx context.Context, name string, metaHeaders http.Header, authConfig *enginetypes.AuthConfig, outStream io.Writer) error
	CreateFromContext(ctx context.Context, tarCtx io.ReadCloser, options *enginetypes.PluginCreateOptions) error
}
