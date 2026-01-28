// Package auto does automatic detection and runtime configuration for certain
// environments.
//
// All top-level functions are not safe to call concurrently.
package auto

import (
	"context"
	"log/slog"
)

var msgs = []func(context.Context){}

func init() {
	CPU()
	Memory()
	Profiling()
}

// PrintLogs uses slog to report any messages queued up from the runs of
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
		slog.DebugContext(ctx, m)
	})
}

// InfoLog is a helper to log static strings.
func infoLog(m string) {
	msgs = append(msgs, func(ctx context.Context) {
		slog.InfoContext(ctx, m)
	})
}
