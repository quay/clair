//go:build go1.19

package auto

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"runtime/debug"
	"strconv"

	"github.com/quay/zlog"
)

// Memory sets the runtime's memory limit based on information gleaned from the
// current process's cgroup. See [debug.SetMemoryLimit] for details on the effects
// of setting the limit. This does mean that attempting to run Clair in an aggressively
// constrained environment may cause excessive CPU time spent in garbage
// collection. Excessive GC can be prevented by increasing the resources allowed or
// pacing Clair as a whole by reducing the CPU allocation or limiting the number of
// concurrent requests.
//
// The process' "memory.max" limit (for cgroups v2) or
// "memory.limit_in_bytes" (for cgroups v1) are the values consulted.
func Memory() {
	root := os.DirFS("/")
	lim, err := memLookup(root)
	switch {
	case err != nil:
		msgs = append(msgs, func(ctx context.Context) {
			zlog.Error(ctx).
				Err(err).
				Msg("unable to guess memory limit")
		})
		return
	case lim == doNothing:
		msgs = append(msgs, func(ctx context.Context) {
			zlog.Info(ctx).
				Msg("no memory limit configured")
		})
		return
	case lim == setMax:
		msgs = append(msgs, func(ctx context.Context) {
			zlog.Info(ctx).Msg("memory limit unset")
		})
		return
	}
	// Following the GC guide and taking a haircut: https://tip.golang.org/doc/gc-guide#Suggested_uses
	tgt := lim - (lim / 20)
	debug.SetMemoryLimit(tgt)
	msgs = append(msgs, func(ctx context.Context) {
		zlog.Info(ctx).
			Int64("lim", lim).
			Int64("target", tgt).
			Msg("set memory limit")
	})
}

const (
	doNothing = -1
	setMax    = -2
)

func memLookup(r fs.FS) (int64, error) {
	b, err := fs.ReadFile(r, "proc/self/cgroup")
	if err != nil {
		return 0, err
	}
	s := bufio.NewScanner(bytes.NewReader(b))
	s.Split(bufio.ScanLines)
	for s.Scan() {
		sl := bytes.SplitN(s.Bytes(), []byte(":"), 3)
		hid, ctls, pb := sl[0], sl[1], sl[2]
		if bytes.Equal(hid, []byte("0")) && len(ctls) == 0 { // If cgroupsv2:
			msgs = append(msgs, func(ctx context.Context) {
				zlog.Debug(ctx).Msg("found cgroups v2")
			})
			n := path.Join("sys/fs/cgroup", string(pb), "memory.max")
			b, err := fs.ReadFile(r, n)
			switch {
			case errors.Is(err, nil):
			case errors.Is(err, fs.ErrNotExist):
				return doNothing, nil
			default:
				return 0, err
			}
			v := string(bytes.TrimSpace(b))
			if v == "max" { // No quota, so bail.
				return setMax, nil
			}
			return strconv.ParseInt(v, 10, 64)
		}
		// If here, we're doing cgroups v1.
		isMem := false
		for _, b := range bytes.Split(ctls, []byte(",")) {
			if bytes.Equal(b, []byte("memory")) {
				isMem = true
				break
			}
		}
		if !isMem { // This line is not the memory group.
			continue
		}
		msgs = append(msgs, func(ctx context.Context) {
			zlog.Debug(ctx).Msg("found cgroups v1 and memory controller")
		})
		prefix := path.Join("sys/fs/cgroup", string(ctls), string(pb))
		// Check for the existence of the named cgroup. If it doesn't exist,
		// look at the root of the controller. The named group not existing
		// probably means the process is in a container and is having remounting
		// tricks done. If, for some reason this is actually the root cgroup,
		// it'll be unlimited and fall back to the default.
		if _, err := fs.Stat(r, prefix); errors.Is(err, fs.ErrNotExist) {
			msgs = append(msgs, func(ctx context.Context) {
				zlog.Debug(ctx).Msg("falling back to root hierarchy")
			})
			prefix = path.Join("sys/fs/cgroup", string(ctls))
		}

		b, err = fs.ReadFile(r, path.Join(prefix, "memory.limit_in_bytes"))
		if err != nil {
			return 0, err
		}
		v := string(bytes.TrimSpace(b))
		return strconv.ParseInt(v, 10, 64)
	}
	if err := s.Err(); err != nil {
		return 0, err
	}
	return 0, nil
}
