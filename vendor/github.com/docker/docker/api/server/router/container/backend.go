package container

import (
	"io"
	"time"

	"github.com/docker/docker/api/types/backend"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/version"
	"github.com/docker/engine-api/types"
	"github.com/docker/engine-api/types/container"
)

// execBackend includes functions to implement to provide exec functionality.
type execBackend interface {
	ContainerExecCreate(config *types.ExecConfig) (string, error)
	ContainerExecInspect(id string) (*backend.ExecInspect, error)
	ContainerExecResize(name string, height, width int) error
	ContainerExecStart(name string, stdin io.ReadCloser, stdout io.Writer, stderr io.Writer) error
	ExecExists(name string) (bool, error)
}

// copyBackend includes functions to implement to provide container copy functionality.
type copyBackend interface {
	ContainerArchivePath(name string, path string) (content io.ReadCloser, stat *types.ContainerPathStat, err error)
	ContainerCopy(name string, res string) (io.ReadCloser, error)
	ContainerExport(name string, out io.Writer) error
	ContainerExtractToDir(name, path string, noOverwriteDirNonDir bool, content io.Reader) error
	ContainerStatPath(name string, path string) (stat *types.ContainerPathStat, err error)
}

// stateBackend includes functions to implement to provide container state lifecycle functionality.
type stateBackend interface {
	ContainerCreate(types.ContainerCreateConfig) (types.ContainerCreateResponse, error)
	ContainerKill(name string, sig uint64) error
	ContainerPause(name string) error
	ContainerRename(oldName, newName string) error
	ContainerResize(name string, height, width int) error
	ContainerRestart(name string, seconds int) error
	ContainerRm(name string, config *types.ContainerRmConfig) error
	ContainerStart(name string, hostConfig *container.HostConfig) error
	ContainerStop(name string, seconds int) error
	ContainerUnpause(name string) error
	ContainerUpdate(name string, hostConfig *container.HostConfig) ([]string, error)
	ContainerWait(name string, timeout time.Duration) (int, error)
}

// monitorBackend includes functions to implement to provide containers monitoring functionality.
type monitorBackend interface {
	ContainerChanges(name string) ([]archive.Change, error)
	ContainerInspect(name string, size bool, version version.Version) (interface{}, error)
	ContainerLogs(name string, config *backend.ContainerLogsConfig, started chan struct{}) error
	ContainerStats(name string, config *backend.ContainerStatsConfig) error
	ContainerTop(name string, psArgs string) (*types.ContainerProcessList, error)

	Containers(config *types.ContainerListOptions) ([]*types.Container, error)
}

// attachBackend includes function to implement to provide container attaching functionality.
type attachBackend interface {
	ContainerAttach(name string, c *backend.ContainerAttachConfig) error
}

// Backend is all the methods that need to be implemented to provide container specific functionality.
type Backend interface {
	execBackend
	copyBackend
	stateBackend
	monitorBackend
	attachBackend
}
