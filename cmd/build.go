// Package cmd provides some common information to clair's binaries.
package cmd // import "github.com/quay/clair/v4/cmd"

import (
	"bytes"
	"context"
	"os/exec"
	"runtime/debug"
	"time"
)

// Injected via git-export(1). See that man page and gitattributes(5).
const (
	// Needs a length check because GitHub zipballs/tarballs don't do the
	// describe and just strip the pattern.
	describe = `$Format:%(describe:match=v4.*)$`
	revision = `$Format:%h (%cI)$`
)

func init() {
	switch {
	case Version != "":
		// Had our version injected at build: do nothing.
	case len(describe) > 0 && describe[0] != '$':
		Version = describe
	case revision[0] == '$':
		// This is a helper for development. In production, we shouldn't assume
		// that the process is running in a git repository or that git is
		// installed. This is quite possibly wrong if run from the wrong working
		// directory.
		Version = `(random source build)`
		ctx, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if _, err := exec.LookPath("git"); err != nil {
			// Couldn't find a git binary: do nothing.
			break
		}
		if err := exec.CommandContext(ctx, "git", "rev-parse", "--show-toplevel").Run(); err != nil {
			// Couldn't find a git repository: do nothing.
			break
		}
		out, err := exec.CommandContext(ctx, "git", "describe").Output()
		if err != nil {
			// Couldn't describe the current commit: do nothing.
			break
		}
		Version = string(bytes.TrimSpace(out))
	default:
		Version = revision
	}

	// If we can read out the current binary's debug info, append the claircore
	// version if there was a replacement.
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, m := range info.Deps {
			if m.Path != "github.com/quay/claircore" {
				continue
			}
			if m.Replace != nil && m.Replace.Version != m.Version {
				Version += " (claircore " + m.Replace.Version + ")"
			}
		}
	}
}

// Version is a version string, injected at release time for release builds.
var Version string
