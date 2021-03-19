package main

import (
	"bytes"
	"context"
	"os/exec"
	"time"
)

// This is a helper for development. In production, we shouldn't assume that the
// process is running in a git repository or that git is installed. Our build
// system does this for release builds.

func init() {
	ctx, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	if Version != "" {
		// Had our version injected at build: do nothing.
		return
	}
	if _, err := exec.LookPath("git"); err != nil {
		// Couldn't find a git binary: do nothing.
		return
	}
	if err := exec.CommandContext(ctx, "git", "rev-parse", "--show-toplevel").Run(); err != nil {
		// Couldn't find a git repository: do nothing.
		return
	}
	out, err := exec.CommandContext(ctx, "git", "describe").Output()
	if err != nil {
		// Couldn't describe the current commit: do nothing.
		return
	}
	Version = string(bytes.TrimSpace(out))
}
