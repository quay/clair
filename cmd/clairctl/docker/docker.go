package docker

import (
	"errors"
	"reflect"

	"github.com/docker/distribution"
	"github.com/docker/distribution/manifest/schema1"
	"github.com/docker/distribution/manifest/schema2"
	"github.com/docker/docker/reference"
	"github.com/jgsqware/clairctl/config"
	"github.com/jgsqware/clairctl/docker/dockercli"
	"github.com/jgsqware/clairctl/docker/dockerdist"
	"github.com/opencontainers/go-digest"
)

//RetrieveManifest get manifest from local or remote docker registry
func RetrieveManifest(imageName string, withExport bool) (image reference.NamedTagged, manifest distribution.Manifest, err error) {

	if !config.IsLocal {
		image, manifest, err = dockerdist.DownloadManifest(imageName, true)
	} else {
		image, manifest, err = dockercli.GetLocalManifest(imageName, withExport)
	}
	return
}

//GetLayerDigests return layer digests from manifest schema1 and schema2
func GetLayerDigests(manifest distribution.Manifest) ([]digest.Digest, error) {
	layers := []digest.Digest{}

	switch manifest.(type) {
	case schema1.SignedManifest:
		for _, l := range manifest.(schema1.SignedManifest).FSLayers {
			layers = append(layers, l.BlobSum)
		}
	case *schema1.SignedManifest:
		for _, l := range manifest.(*schema1.SignedManifest).FSLayers {
			layers = append(layers, l.BlobSum)
		}
	case *schema2.DeserializedManifest:
		for _, d := range manifest.(*schema2.DeserializedManifest).Layers {
			layers = append(layers, d.Digest)
		}
	case schema2.DeserializedManifest:
		for _, d := range manifest.(schema2.DeserializedManifest).Layers {
			layers = append(layers, d.Digest)
		}
	default:
		return nil, errors.New("Not supported manifest schema type: " + reflect.TypeOf(manifest).String())
	}

	return layers, nil
}
