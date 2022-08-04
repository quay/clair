//go:build linux && go1.19

package auto

import (
	"context"
	"fmt"
	"testing"
	"testing/fstest"

	"github.com/quay/zlog"
)

type memTestcase struct {
	In   fstest.MapFS
	Err  error
	Name string
	Want int64
}

func (tc memTestcase) Run(ctx context.Context, t *testing.T) {
	t.Helper()
	t.Run(tc.Name, func(t *testing.T) {
		t.Helper()
		ctx := zlog.Test(ctx, t)
		lim, err := memLookup(tc.In)
		if err != tc.Err {
			t.Error(err)
		}
		if got, want := lim, tc.Want; tc.Err == nil && got != want {
			t.Errorf("got: %v, want: %v", got, want)
		}
		PrintLogs(ctx)
	})
}

func TestMemoryDetection(t *testing.T) {
	const (
		limInt   = 268435456
		noLimInt = -1
	)
	var (
		lim   = &fstest.MapFile{Data: []byte(fmt.Sprintln(limInt))}
		noLim = &fstest.MapFile{Data: []byte(fmt.Sprintln(noLimInt))}
	)
	ctx := zlog.Test(context.Background(), t)
	t.Run("V1", func(t *testing.T) {
		tt := []memTestcase{
			{
				Name: "NoLimit",
				In: fstest.MapFS{
					"proc/self/cgroup": cgv1,
					"sys/fs/cgroup/memory/user.slice/user-1000.slice/session-4.scope/memory.limit_in_bytes": noLim,
				},
				Want: noLimInt,
			},
			{
				Name: "RootFallback",
				In: fstest.MapFS{
					"proc/self/cgroup":                           cgv1,
					"sys/fs/cgroup/memory/memory.limit_in_bytes": noLim,
				},
				Want: noLimInt,
			},
			{
				Name: "256MiB",
				In: fstest.MapFS{
					"proc/self/cgroup": cgv1,
					"sys/fs/cgroup/memory/user.slice/user-1000.slice/session-4.scope/memory.limit_in_bytes": lim,
				},
				Want: limInt,
			},
		}
		ctx := zlog.Test(ctx, t)
		for _, tc := range tt {
			tc.Run(ctx, t)
		}
	})
	t.Run("V2", func(t *testing.T) {
		tt := []memTestcase{
			{
				Name: "NoLimit",
				In:   fstest.MapFS{"proc/self/cgroup": cgv2},
				Want: noLimInt,
			},
			{
				Name: "LimitMax",
				In: fstest.MapFS{
					"proc/self/cgroup": cgv2,
					"sys/fs/cgroup/memory.max": &fstest.MapFile{
						Data: []byte("max\n"),
					},
				},
				Want: setMax,
			},
			{
				Name: "256MiB",
				In: fstest.MapFS{
					"proc/self/cgroup":         cgv2,
					"sys/fs/cgroup/memory.max": lim,
				},
				Want: limInt,
			},
		}
		ctx := zlog.Test(ctx, t)
		for _, tc := range tt {
			tc.Run(ctx, t)
		}
	})
}
