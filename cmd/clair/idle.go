package main

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// IdleMontior holds idle tracking machinery.
type idleMonitor struct {
	timer   *time.Timer
	timeout time.Duration
	ct      atomic.Uint32
}

// NewIdleMonitor starts a goroutine to call "f" if the duration "timeout"
// passes with no active HTTP connections.
//
// The goroutine will also exit if the passed context is canceled.
func newIdleMonitor(ctx context.Context, timeout time.Duration, f context.CancelCauseFunc) idleMonitor {
	timer := time.NewTimer(timeout)
	go func() {
		select {
		case <-ctx.Done():
		case <-timer.C:
			f(nil) // TODO(hank) Add a specific "idle timeout" condition?
		}
	}()

	return idleMonitor{
		timer:   timer,
		timeout: timeout,
	}
}

// ServerHook is a function suitable for use as [http.Server.ConnState].
//
// This hook watches connection state changes, starting an idle timer when there
// are no open connections. The timer will be stopped if new connections arrive
// during the timeout period.
func (m *idleMonitor) ServerHook(_ net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		if m.ct.Add(1) == 1 {
			m.timer.Stop()
		}
	case http.StateClosed, http.StateHijacked:
		if m.ct.Add(^uint32(0)) == 0 {
			m.timer.Reset(m.timeout)
		}
	}
}
