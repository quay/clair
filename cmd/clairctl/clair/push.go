package clair

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/clair/api/v1"
	"github.com/docker/distribution"
	"github.com/docker/distribution/manifest/schema1"
	"github.com/docker/distribution/manifest/schema2"
	"github.com/docker/docker/reference"
	"github.com/coreos/clair/cmd/clairctl/docker/dockerdist"
)

// ErrUnanalizedLayer is returned when the layer was not correctly analyzed
var ErrUnanalizedLayer = errors.New("layer cannot be analyzed")

var registryMapping map[string]string

func Push(image reference.NamedTagged, manifest distribution.Manifest) error {
	layers, err := newLayering(image)
	if err != nil {
		return err
	}

	switch manifest.(type) {
	case schema1.SignedManifest:
		for _, l := range manifest.(schema1.SignedManifest).FSLayers {
			layers.digests = append(layers.digests, l.BlobSum.String())
		}
		return layers.pushAll()
	case *schema1.SignedManifest:
		for _, l := range manifest.(*schema1.SignedManifest).FSLayers {
			layers.digests = append(layers.digests, l.BlobSum.String())
		}
		return layers.pushAll()
	case schema2.DeserializedManifest:
		for _, l := range manifest.(schema2.DeserializedManifest).Layers {
			layers.digests = append(layers.digests, l.Digest.String())
		}
		return layers.pushAll()
	case *schema2.DeserializedManifest:
		for _, l := range manifest.(*schema2.DeserializedManifest).Layers {
			layers.digests = append(layers.digests, l.Digest.String())
		}
		return layers.pushAll()
	default:
		return errors.New("Unsupported Schema version.")
	}
}

func pushLayer(layer v1.LayerEnvelope) error {
	lJSON, err := json.Marshal(layer)
	if err != nil {
		return fmt.Errorf("marshalling layer: %v", err)
	}

	lURI := fmt.Sprintf("%v/layers", uri)
	request, err := http.NewRequest("POST", lURI, bytes.NewBuffer(lJSON))
	if err != nil {
		return fmt.Errorf("creating 'add layer' request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := (&http.Client{}).Do(request)

	if err != nil {
		return fmt.Errorf("pushing layer to clair: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != 201 {
		if response.StatusCode == 422 {
			return ErrUnanalizedLayer
		}
		return fmt.Errorf("receiving http error: %d", response.StatusCode)
	}

	return nil
}

func blobsURI(registry string, name string, digest string) string {
	return strings.Join([]string{registry, name, "blobs", digest}, "/")
}

func insertRegistryMapping(layerDigest string, registryURI string) {

	hostURL, _ := dockerdist.GetPushURL(registryURI)
	log.Debugf("Saving %s[%s]", layerDigest, hostURL.String())
	registryMapping[layerDigest] = hostURL.String()
}

//GetRegistryMapping return the registryURI corresponding to the layerID passed as parameter
func GetRegistryMapping(layerDigest string) (string, error) {
	registryURI, present := registryMapping[layerDigest]
	if !present {
		return "", fmt.Errorf("%v mapping not found", layerDigest)
	}
	return registryURI, nil
}

func init() {
	registryMapping = map[string]string{}
}
