package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/quay/clair/config"
	"golang.org/x/sys/unix"
)

// ListenAPI returns a listener to serve the API on.
//
// # Linux
//
// The Linux implementation checks if the process has been passed a file
// descriptor to use by systemd. If there is only 1, it will be used to serve
// the API service. If there's more than one, the descriptor with the associated
// name "api" will be used.
func listenAPI(ctx context.Context, cfg *config.Config) (net.Listener, error) {
	const (
		fdName = `api`
		msg    = `unable to use passed files`
	)
	fds, err := getFDs()
	switch {
	case err != nil:
		slog.WarnContext(ctx, msg, "reason", err)
	case len(fds) == 0:
	case len(fds) == 1:
		f := os.NewFile(fds[0].FD, fds[0].Name)
		defer f.Close()
		return net.FileListener(f)
	default:
		for _, fd := range fds {
			if fd.Name == fdName {
				f := os.NewFile(fd.FD, fd.Name)
				defer f.Close()
				return net.FileListener(f)
			}
		}
		slog.WarnContext(ctx, msg,
			"reason", fmt.Sprintf("none with name %q", fdName))
	}

	return net.Listen(cfg.API.V1.Network, getAPIv1Address(cfg))
}

// ListenIntrospection returns a listener to serve the Introspection endpoints
// on.
//
// # Linux
//
// The Linux implementation checks if the process has been passed a file
// descriptor to use by systemd. If there's more than one, the descriptor with
// the associated name "introspection" will be used.
func listenIntrospection(ctx context.Context, cfg *config.Config) (net.Listener, error) {
	const (
		fdName = `introspection`
		msg    = `unable to use passed files`
	)
	fds, err := getFDs()
	switch {
	case err != nil:
		slog.WarnContext(ctx, msg, "reason", err)
	case len(fds) == 0:
	default:
		for _, fd := range fds {
			if fd.Name == fdName {
				f := os.NewFile(fd.FD, fd.Name)
				defer f.Close()
				return net.FileListener(f)
			}
		}
		slog.WarnContext(ctx, msg,
			"reason", fmt.Sprintf("none with name %q", fdName))
	}

	return net.Listen(cfg.Introspection.Network, getIntrospectionAddress(cfg))
}

// GetFDs implements [sd_listen_fds(3)].
//
// [sd_listen_fds(3)]: https://www.freedesktop.org/software/systemd/man/latest/sd_listen_fds.html
var getFDs = sync.OnceValues(func() ([]passedFD, error) {
	const (
		fdsStart = 3
		errMsg   = "failed to parse environment variable %q: %w"

		pidKey   = `LISTEN_PID`
		pidfdKey = `LISTEN_PIDFDID`
		countKey = `LISTEN_FDS`
		namesKey = `LISTEN_FDNAMES`
	)
	errNoVar := errors.New("no environment variable")
	tryParse := func(key string) (uint64, error) {
		s, ok := os.LookupEnv(key)
		if !ok {
			return 0, errNoVar
		}
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, fmt.Errorf(errMsg, key, err)
		}
		return n, nil
	}
	// Always unset the environment variables. This is equivalent to the
	// "unset_environment" argument to sd_listen_fds(3).
	//
	// SAFETY: These keys are only read in this function, which is only run
	// once.
	defer func() {
		os.Unsetenv(pidKey)
		os.Unsetenv(pidfdKey)
		os.Unsetenv(countKey)
		os.Unsetenv(namesKey)
	}()

	// Check that the current process is the target of passed fds.
	tgtPid, err := tryParse(pidKey)
	switch err {
	case nil:
	case errNoVar:
		return nil, nil
	default:
		return nil, err
	}
	pid := os.Getpid()
	if tgtPid != uint64(pid) {
		return nil, nil
	}

	// If a new enough kernel+systemd to also pass the pidfd ID, check that:
	var kernelOK, varOK bool
	fd, err := unix.PidfdOpen(pid, 0)
	switch {
	case err == nil:
		kernelOK = true
	case errors.Is(err, unix.ENOSYS): // Old kernel
	default:
		return nil, fmt.Errorf(`unexpected error: %w`, err)
	}
	tgtPidfdid, err := tryParse(pidfdKey)
	switch err {
	case nil:
		varOK = true
	case errNoVar:
	default:
		return nil, err
	}
	if kernelOK && varOK {
		buf := new(unix.Statfs_t)
		if err := unix.Fstatfs(fd, buf); err != nil {
			return nil, fmt.Errorf(`unexpected %q error: %w`, "fstatfs", err)
		}
		if buf.Type != unix.PID_FS_MAGIC {
			return nil, fmt.Errorf(`unexpected error: incorrect magic on pidfd`)
		}

		stat := new(unix.Stat_t)
		if err := unix.Fstat(fd, stat); err != nil {
			return nil, fmt.Errorf(`unexpected %q error: %w`, "fstat", err)
		}
		if tgtPidfdid != stat.Ino {
			return nil, nil
		}
	}

	// Get the count of passed fds.
	ct, err := tryParse(countKey)
	switch err {
	case nil:
	case errNoVar:
		return nil, fmt.Errorf("parsing %q: %w", countKey, err)
	default:
		return nil, err
	}
	// Get the associated names or use a default.
	ns := make([]string, int(ct))
	if s, ok := os.LookupEnv(namesKey); ok {
		ns = strings.Split(s, ":")
		// This strict length check is the libsystemd behavior.
		if len(ns) != int(ct) {
			return nil, fmt.Errorf(errMsg, namesKey, err)
		}
	}

	// Build and return the list of fds.
	fds := make([]passedFD, ct)
	for i, n := range ns {
		fds[i] = passedFD{
			Name: cmp.Or(n, `unknown`),
			FD:   uintptr(i + fdsStart),
		}
	}
	return fds, nil
})

// PassedFD is a file descriptor passed by systemd and the associated name.
type passedFD struct {
	Name string
	FD   uintptr
}
