// Package auto does automatic detection and runtime configuration for certain
// environments.
//
// All top-level functions are not safe to call concurrently.
package auto

import (
	"context"

	"github.com/quay/zlog"
)

var msgs = []func(context.Context){}

func init() {
	CPU()
	Memory()
	Profiling()
}

// PrintLogs uses zlog to report any messages queued up from the runs of
// functions since the last call to PrintLogs.
func PrintLogs(ctx context.Context) {
	for _, f := range msgs {
		f(ctx)
	}
	msgs = msgs[:0]
}

// DebugLog is a helper to log static strings.
func debugLog(m string) {
	msgs = append(msgs, func(ctx context.Context) {
		zlog.Debug(ctx).Msg(m)
	})
}

// InfoLog is a helper to log static strings.
func infoLog(m string) {
	msgs = append(msgs, func(ctx context.Context) {
		zlog.Info(ctx).Msg(m)
	})
}
