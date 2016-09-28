package daemon

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/docker/builder"
	"github.com/docker/docker/container"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/chrootarchive"
	"github.com/docker/docker/pkg/idtools"
	"github.com/docker/docker/pkg/ioutils"
	"github.com/docker/engine-api/types"
)

// ErrExtractPointNotDirectory is used to convey that the operation to extract
// a tar archive to a directory in a container has failed because the specified
// path does not refer to a directory.
var ErrExtractPointNotDirectory = errors.New("extraction point is not a directory")

// ContainerCopy performs a deprecated operation of archiving the resource at
// the specified path in the container identified by the given name.
func (daemon *Daemon) ContainerCopy(name string, res string) (io.ReadCloser, error) {
	container, err := daemon.GetContainer(name)
	if err != nil {
		return nil, err
	}

	if res[0] == '/' || res[0] == '\\' {
		res = res[1:]
	}

	return daemon.containerCopy(container, res)
}

// ContainerStatPath stats the filesystem resource at the specified path in the
// container identified by the given name.
func (daemon *Daemon) ContainerStatPath(name string, path string) (stat *types.ContainerPathStat, err error) {
	container, err := daemon.GetContainer(name)
	if err != nil {
		return nil, err
	}

	return daemon.containerStatPath(container, path)
}

// ContainerArchivePath creates an archive of the filesystem resource at the
// specified path in the container identified by the given name. Returns a
// tar archive of the resource and whether it was a directory or a single file.
func (daemon *Daemon) ContainerArchivePath(name string, path string) (content io.ReadCloser, stat *types.ContainerPathStat, err error) {
	container, err := daemon.GetContainer(name)
	if err != nil {
		return nil, nil, err
	}

	return daemon.containerArchivePath(container, path)
}

// ContainerExtractToDir extracts the given archive to the specified location
// in the filesystem of the container identified by the given name. The given
// path must be of a directory in the container. If it is not, the error will
// be ErrExtractPointNotDirectory. If noOverwriteDirNonDir is true then it will
// be an error if unpacking the given content would cause an existing directory
// to be replaced with a non-directory and vice versa.
func (daemon *Daemon) ContainerExtractToDir(name, path string, noOverwriteDirNonDir bool, content io.Reader) error {
	container, err := daemon.GetContainer(name)
	if err != nil {
		return err
	}

	return daemon.containerExtractToDir(container, path, noOverwriteDirNonDir, content)
}

// containerStatPath stats the filesystem resource at the specified path in this
// container. Returns stat info about the resource.
func (daemon *Daemon) containerStatPath(container *container.Container, path string) (stat *types.ContainerPathStat, err error) {
	container.Lock()
	defer container.Unlock()

	if err = daemon.Mount(container); err != nil {
		return nil, err
	}
	defer daemon.Unmount(container)

	err = daemon.mountVolumes(container)
	defer container.UnmountVolumes(true, daemon.LogVolumeEvent)
	if err != nil {
		return nil, err
	}

	resolvedPath, absPath, err := container.ResolvePath(path)
	if err != nil {
		return nil, err
	}

	return container.StatPath(resolvedPath, absPath)
}

// containerArchivePath creates an archive of the filesystem resource at the specified
// path in this container. Returns a tar archive of the resource and stat info
// about the resource.
func (daemon *Daemon) containerArchivePath(container *container.Container, path string) (content io.ReadCloser, stat *types.ContainerPathStat, err error) {
	container.Lock()

	defer func() {
		if err != nil {
			// Wait to unlock the container until the archive is fully read
			// (see the ReadCloseWrapper func below) or if there is an error
			// before that occurs.
			container.Unlock()
		}
	}()

	if err = daemon.Mount(container); err != nil {
		return nil, nil, err
	}

	defer func() {
		if err != nil {
			// unmount any volumes
			container.UnmountVolumes(true, daemon.LogVolumeEvent)
			// unmount the container's rootfs
			daemon.Unmount(container)
		}
	}()

	if err = daemon.mountVolumes(container); err != nil {
		return nil, nil, err
	}

	resolvedPath, absPath, err := container.ResolvePath(path)
	if err != nil {
		return nil, nil, err
	}

	stat, err = container.StatPath(resolvedPath, absPath)
	if err != nil {
		return nil, nil, err
	}

	// We need to rebase the archive entries if the last element of the
	// resolved path was a symlink that was evaluated and is now different
	// than the requested path. For example, if the given path was "/foo/bar/",
	// but it resolved to "/var/lib/docker/containers/{id}/foo/baz/", we want
	// to ensure that the archive entries start with "bar" and not "baz". This
	// also catches the case when the root directory of the container is
	// requested: we want the archive entries to start with "/" and not the
	// container ID.
	data, err := archive.TarResourceRebase(resolvedPath, filepath.Base(absPath))
	if err != nil {
		return nil, nil, err
	}

	content = ioutils.NewReadCloserWrapper(data, func() error {
		err := data.Close()
		container.UnmountVolumes(true, daemon.LogVolumeEvent)
		daemon.Unmount(container)
		container.Unlock()
		return err
	})

	daemon.LogContainerEvent(container, "archive-path")

	return content, stat, nil
}

// containerExtractToDir extracts the given tar archive to the specified location in the
// filesystem of this container. The given path must be of a directory in the
// container. If it is not, the error will be ErrExtractPointNotDirectory. If
// noOverwriteDirNonDir is true then it will be an error if unpacking the
// given content would cause an existing directory to be replaced with a non-
// directory and vice versa.
func (daemon *Daemon) containerExtractToDir(container *container.Container, path string, noOverwriteDirNonDir bool, content io.Reader) (err error) {
	container.Lock()
	defer container.Unlock()

	if err = daemon.Mount(container); err != nil {
		return err
	}
	defer daemon.Unmount(container)

	err = daemon.mountVolumes(container)
	defer container.UnmountVolumes(true, daemon.LogVolumeEvent)
	if err != nil {
		return err
	}

	// The destination path needs to be resolved to a host path, with all
	// symbolic links followed in the scope of the container's rootfs. Note
	// that we do not use `container.ResolvePath(path)` here because we need
	// to also evaluate the last path element if it is a symlink. This is so
	// that you can extract an archive to a symlink that points to a directory.

	// Consider the given path as an absolute path in the container.
	absPath := archive.PreserveTrailingDotOrSeparator(filepath.Join(string(filepath.Separator), path), path)

	// This will evaluate the last path element if it is a symlink.
	resolvedPath, err := container.GetResourcePath(absPath)
	if err != nil {
		return err
	}

	stat, err := os.Lstat(resolvedPath)
	if err != nil {
		return err
	}

	if !stat.IsDir() {
		return ErrExtractPointNotDirectory
	}

	// Need to check if the path is in a volume. If it is, it cannot be in a
	// read-only volume. If it is not in a volume, the container cannot be
	// configured with a read-only rootfs.

	// Use the resolved path relative to the container rootfs as the new
	// absPath. This way we fully follow any symlinks in a volume that may
	// lead back outside the volume.
	//
	// The Windows implementation of filepath.Rel in golang 1.4 does not
	// support volume style file path semantics. On Windows when using the
	// filter driver, we are guaranteed that the path will always be
	// a volume file path.
	var baseRel string
	if strings.HasPrefix(resolvedPath, `\\?\Volume{`) {
		if strings.HasPrefix(resolvedPath, container.BaseFS) {
			baseRel = resolvedPath[len(container.BaseFS):]
			if baseRel[:1] == `\` {
				baseRel = baseRel[1:]
			}
		}
	} else {
		baseRel, err = filepath.Rel(container.BaseFS, resolvedPath)
	}
	if err != nil {
		return err
	}
	// Make it an absolute path.
	absPath = filepath.Join(string(filepath.Separator), baseRel)

	toVolume, err := checkIfPathIsInAVolume(container, absPath)
	if err != nil {
		return err
	}

	if !toVolume && container.HostConfig.ReadonlyRootfs {
		return ErrRootFSReadOnly
	}

	uid, gid := daemon.GetRemappedUIDGID()
	options := &archive.TarOptions{
		NoOverwriteDirNonDir: noOverwriteDirNonDir,
		ChownOpts: &archive.TarChownOptions{
			UID: uid, GID: gid, // TODO: should all ownership be set to root (either real or remapped)?
		},
	}
	if err := chrootarchive.Untar(content, resolvedPath, options); err != nil {
		return err
	}

	daemon.LogContainerEvent(container, "extract-to-dir")

	return nil
}

func (daemon *Daemon) containerCopy(container *container.Container, resource string) (rc io.ReadCloser, err error) {
	container.Lock()

	defer func() {
		if err != nil {
			// Wait to unlock the container until the archive is fully read
			// (see the ReadCloseWrapper func below) or if there is an error
			// before that occurs.
			container.Unlock()
		}
	}()

	if err := daemon.Mount(container); err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			// unmount any volumes
			container.UnmountVolumes(true, daemon.LogVolumeEvent)
			// unmount the container's rootfs
			daemon.Unmount(container)
		}
	}()

	if err := daemon.mountVolumes(container); err != nil {
		return nil, err
	}

	basePath, err := container.GetResourcePath(resource)
	if err != nil {
		return nil, err
	}
	stat, err := os.Stat(basePath)
	if err != nil {
		return nil, err
	}
	var filter []string
	if !stat.IsDir() {
		d, f := filepath.Split(basePath)
		basePath = d
		filter = []string{f}
	} else {
		filter = []string{filepath.Base(basePath)}
		basePath = filepath.Dir(basePath)
	}
	archive, err := archive.TarWithOptions(basePath, &archive.TarOptions{
		Compression:  archive.Uncompressed,
		IncludeFiles: filter,
	})
	if err != nil {
		return nil, err
	}

	reader := ioutils.NewReadCloserWrapper(archive, func() error {
		err := archive.Close()
		container.UnmountVolumes(true, daemon.LogVolumeEvent)
		daemon.Unmount(container)
		container.Unlock()
		return err
	})
	daemon.LogContainerEvent(container, "copy")
	return reader, nil
}

// CopyOnBuild copies/extracts a source FileInfo to a destination path inside a container
// specified by a container object.
// TODO: make sure callers don't unnecessarily convert destPath with filepath.FromSlash (Copy does it already).
// CopyOnBuild should take in abstract paths (with slashes) and the implementation should convert it to OS-specific paths.
func (daemon *Daemon) CopyOnBuild(cID string, destPath string, src builder.FileInfo, decompress bool) error {
	srcPath := src.Path()
	destExists := true
	destDir := false
	rootUID, rootGID := daemon.GetRemappedUIDGID()

	// Work in daemon-local OS specific file paths
	destPath = filepath.FromSlash(destPath)

	c, err := daemon.GetContainer(cID)
	if err != nil {
		return err
	}
	err = daemon.Mount(c)
	if err != nil {
		return err
	}
	defer daemon.Unmount(c)

	dest, err := c.GetResourcePath(destPath)
	if err != nil {
		return err
	}

	// Preserve the trailing slash
	// TODO: why are we appending another path separator if there was already one?
	if strings.HasSuffix(destPath, string(os.PathSeparator)) || destPath == "." {
		destDir = true
		dest += string(os.PathSeparator)
	}

	destPath = dest

	destStat, err := os.Stat(destPath)
	if err != nil {
		if !os.IsNotExist(err) {
			//logrus.Errorf("Error performing os.Stat on %s. %s", destPath, err)
			return err
		}
		destExists = false
	}

	uidMaps, gidMaps := daemon.GetUIDGIDMaps()
	archiver := &archive.Archiver{
		Untar:   chrootarchive.Untar,
		UIDMaps: uidMaps,
		GIDMaps: gidMaps,
	}

	if src.IsDir() {
		// copy as directory
		if err := archiver.CopyWithTar(srcPath, destPath); err != nil {
			return err
		}
		return fixPermissions(srcPath, destPath, rootUID, rootGID, destExists)
	}
	if decompress && archive.IsArchivePath(srcPath) {
		// Only try to untar if it is a file and that we've been told to decompress (when ADD-ing a remote file)

		// First try to unpack the source as an archive
		// to support the untar feature we need to clean up the path a little bit
		// because tar is very forgiving.  First we need to strip off the archive's
		// filename from the path but this is only added if it does not end in slash
		tarDest := destPath
		if strings.HasSuffix(tarDest, string(os.PathSeparator)) {
			tarDest = filepath.Dir(destPath)
		}

		// try to successfully untar the orig
		err := archiver.UntarPath(srcPath, tarDest)
		/*
			if err != nil {
				logrus.Errorf("Couldn't untar to %s: %v", tarDest, err)
			}
		*/
		return err
	}

	// only needed for fixPermissions, but might as well put it before CopyFileWithTar
	if destDir || (destExists && destStat.IsDir()) {
		destPath = filepath.Join(destPath, src.Name())
	}

	if err := idtools.MkdirAllNewAs(filepath.Dir(destPath), 0755, rootUID, rootGID); err != nil {
		return err
	}
	if err := archiver.CopyFileWithTar(srcPath, destPath); err != nil {
		return err
	}

	return fixPermissions(srcPath, destPath, rootUID, rootGID, destExists)
}
