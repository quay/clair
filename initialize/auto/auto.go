// Package auto does automatic detection and runtime configuration for certain
// environments.
package auto

import (
	"context"
)

var msgs = []func(context.Context){}

func init() {
	CPU()
}

// Logs uses zlog to report any messages queued up during initialization.
func Logs(ctx context.Context) {
	for _, f := range msgs {
		f(ctx)
	}
	msgs = msgs[:0]
}
