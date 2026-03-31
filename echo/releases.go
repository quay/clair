package echo

import (
	"sync"

	"github.com/quay/claircore"
)

var releases sync.Map

func mkDist(ver string) *claircore.Distribution {
	v, _ := releases.LoadOrStore(ver, &claircore.Distribution{
		PrettyName: "Echo Linux",
		Name:       "Echo Linux",
		VersionID:  ver,
		DID:        "echo",
	})
	return v.(*claircore.Distribution)
}

func getDist() *claircore.Distribution {
	v, ok := releases.Load("generic")
	if !ok {
		return mkDist("generic")
	}
	return v.(*claircore.Distribution)
}

const (
	// linkPrefix is the URL prefix for Echo advisory links.
	linkPrefix = `https://advisory.echohq.com/cve/`

	// DefaultAdvisoryURL is the URL for the Echo advisory data.
	//
	//doc:url updater
	DefaultAdvisoryURL = `https://advisory.echohq.com/data.json`
)
