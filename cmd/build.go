// Package cmd provides some common information to clair's binaries.
package cmd // import "github.com/quay/clair/v4/cmd"

import (
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Injected via git-export(1). See that man page and gitattributes(5).
const (
	// Needs a length check because GitHub zipballs/tarballs don't do the
	// describe and just strip the pattern.
	describe = `$Format:%(describe:match=v4.*)$`
	revision = `$Format:%h (%cI)$`
)

var versionInfo = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Namespace: "clair",
		Subsystem: "cmd",
		Name:      "version_info",
		Help:      "Version information.",
	},
	[]string{
		"claircore_version",
		"goversion",
		"modified",
		"revision",
		"version",
	},
)

func init() {
	if revision[0] != '$' {
		_, d, _ := strings.Cut(revision, "(")
		t, err := time.Parse(time.RFC3339, strings.TrimSuffix(d, ")"))
		if err == nil {
			CommitDate = t
		}
	}

	meta := prometheus.Labels{
		"claircore_version": "",
		"goversion":         runtime.Version(),
		"modified":          "",
		"revision":          revision,
		"version":           "",
	}
	info, infoOK := debug.ReadBuildInfo()
	var vcs []string
	var core string
	if infoOK {
		// If not OK, built without modules? Weird.
		for _, s := range info.Settings {
			switch s.Key {
			case `vcs.revision`:
				meta["revision"] = s.Value
				vcs = append(vcs, `rev`, s.Value)
			case `vcs.modified`:
				meta["modified"] = s.Value
				if s.Value == `true` {
					vcs = append(vcs, `(dirty)`)
				}
			}
		}
		// If we can read out the current binary's debug info, find the
		// claircore version.
		for _, m := range info.Deps {
			if m.Path != "github.com/quay/claircore" {
				continue
			}
			core = m.Version
			if m.Replace != nil && m.Replace.Version != m.Version {
				core = m.Replace.Version
			}
		}
		meta["claircore_version"] = core
	}

	switch {
	case Version != "":
		// Had our version injected at build: do nothing.
	case len(describe) > 0 && describe[0] != '$' && !strings.HasPrefix(describe, "%(describe:"):
		// Some git versions apparently don't know about the describe format
		// verb, so need to check that it's not just "%(describe..."
		Version = describe
	case revision[0] == '$':
		Version = `(random source build)`
		if len(vcs) == 0 {
			// A `go run` invocation, perhaps.
			break
		}
		Version = strings.Join(vcs, " ")
	default:
		Version = revision
	}
	meta["version"] = Version
	if core != "" {
		Version += " (claircore " + core + ")"
	}
	versionInfo.With(meta).Set(1)
}

// Version is a version string, injected at release time for release builds.
var Version string

// CommitDate is the best guess of the source commit date.
//
// May be zero when the resulting code is not produced by a git export.
var CommitDate time.Time
