package auto

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"runtime"
	"strconv"

	"github.com/quay/zlog"
)

// CPU guesses a good number for GOMAXPROCS based on information gleaned from
// the current process's cgroup.
func CPU() {
	if os.Getenv("GOMAXPROCS") != "" {
		msgs = append(msgs, func(ctx context.Context) {
			zlog.Info(ctx).Msg("GOMAXPROCS set in the environment, skipping auto detection")
		})
		return
	}
	root := os.DirFS("/")
	gmp, err := cgLookup(root)
	if err != nil {
		msgs = append(msgs, func(ctx context.Context) {
			zlog.Error(ctx).
				Err(err).
				Msg("unable to guess GOMAXPROCS value")
		})
		return
	}
	prev := runtime.GOMAXPROCS(gmp)
	msgs = append(msgs, func(ctx context.Context) {
		zlog.Info(ctx).
			Int("cur", gmp).
			Int("prev", prev).
			Msg("set GOMAXPROCS value")
	})
}

func cgLookup(r fs.FS) (int, error) {
	var gmp int
	b, err := fs.ReadFile(r, "proc/self/cgroup")
	if err != nil {
		return gmp, err
	}
	var q, p uint64 = 0, 1
	s := bufio.NewScanner(bytes.NewReader(b))
	s.Split(bufio.ScanLines)
	for s.Scan() {
		sl := bytes.SplitN(s.Bytes(), []byte(":"), 3)
		hid, ctls, pb := sl[0], sl[1], sl[2]
		if bytes.Equal(hid, []byte("0")) && len(ctls) == 0 { // If cgroupsv2:
			msgs = append(msgs, func(ctx context.Context) {
				zlog.Debug(ctx).Msg("found cgroups v2")
			})
			n := path.Join("sys/fs/cgroup", string(pb), "cpu.max")
			b, err := fs.ReadFile(r, n)
			if err != nil {
				return gmp, err
			}
			l := bytes.Fields(b)
			qt, per := string(l[0]), string(l[1])
			if qt == "max" {
				// No quota, so bail.
				msgs = append(msgs, func(ctx context.Context) {
					zlog.Info(ctx).Msg("no CPU quota set, using default")
				})
				return gmp, nil
			}
			q, err = strconv.ParseUint(qt, 10, 64)
			if err != nil {
				return gmp, err
			}
			p, err = strconv.ParseUint(per, 10, 64)
			if err != nil {
				return gmp, err
			}
			break
		}
		// If here, we're doing cgroups v1.
		isCPU := false
		for _, b := range bytes.Split(ctls, []byte(",")) {
			if bytes.Equal(b, []byte("cpu")) {
				isCPU = true
				break
			}
		}
		if !isCPU {
			// This line is not the cpu group.
			continue
		}
		msgs = append(msgs, func(ctx context.Context) {
			zlog.Debug(ctx).Msg("found cgroups v1 and cpu controller")
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

		b, err = fs.ReadFile(r, path.Join(prefix, "cpu.cfs_quota_us"))
		if err != nil {
			return gmp, err
		}
		qi, err := strconv.ParseInt(string(bytes.TrimSpace(b)), 10, 64)
		if err != nil {
			return gmp, err
		}
		if qi == -1 {
			// No quota, so bail.
			msgs = append(msgs, func(ctx context.Context) {
				zlog.Info(ctx).Msg("no CPU quota set, using default")
			})
			return gmp, nil
		}
		q = uint64(qi)
		b, err = fs.ReadFile(r, path.Join(prefix, "cpu.cfs_period_us"))
		if err != nil {
			return gmp, err
		}
		p, err = strconv.ParseUint(string(bytes.TrimSpace(b)), 10, 64)
		if err != nil {
			return gmp, err
		}
		break
	}
	if err := s.Err(); err != nil {
		return gmp, err
	}
	gmp = int(q / p)
	return gmp, nil
}
