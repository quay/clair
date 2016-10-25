package docker

import (
	"github.com/coreos/clair/cmd/clairctl/config"
	"github.com/coreos/clair/cmd/clairctl/docker/dockercli"
	"github.com/coreos/clair/cmd/clairctl/docker/dockerdist"
	"github.com/docker/distribution/manifest/schema1"
	"github.com/docker/docker/reference"
)

//RetrieveManifest get manifest from local or remote docker registry
func RetrieveManifest(imageName string, withExport bool) (image reference.Named, manifest schema1.SignedManifest, err error) {
	if !config.IsLocal {
		image, manifest, err = dockerdist.DownloadV1Manifest(imageName, true)
	} else {
		image, manifest, err = dockercli.GetLocalManifest(imageName, withExport)
	}
	return
}
