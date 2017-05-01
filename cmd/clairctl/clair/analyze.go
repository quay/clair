package clair

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/coreos/clair/api/v1"
	"github.com/docker/distribution"
	"github.com/docker/distribution/manifest/schema1"
	"github.com/docker/distribution/manifest/schema2"
	"github.com/docker/docker/reference"
)

//Analyze return Clair Image analysis
func Analyze(image reference.NamedTagged, manifest distribution.Manifest) ImageAnalysis {
	layers, err := newLayering(image)
	if err != nil {
		log.Fatalf("cannot parse manifest")
		return ImageAnalysis{}
	}

	switch manifest.(type) {
	case schema1.SignedManifest:

		for _, l := range manifest.(schema1.SignedManifest).FSLayers {
			layers.digests = append(layers.digests, l.BlobSum.String())
		}
		return layers.analyze()
	case *schema1.SignedManifest:
		for _, l := range manifest.(*schema1.SignedManifest).FSLayers {
			layers.digests = append(layers.digests, l.BlobSum.String())
		}
		return layers.analyze()
	case schema2.DeserializedManifest:
		log.Debugf("json: %v", image)
		for _, l := range manifest.(schema2.DeserializedManifest).Layers {
			layers.digests = append(layers.digests, l.Digest.String())
		}
		return layers.analyze()
	case *schema2.DeserializedManifest:
		log.Debugf("json: %v", image)
		for _, l := range manifest.(*schema2.DeserializedManifest).Layers {
			layers.digests = append(layers.digests, l.Digest.String())
		}
		return layers.analyze()
	default:
		log.Fatalf("Unsupported Schema version.")
		return ImageAnalysis{}
	}
}

func analyzeLayer(id string) (v1.LayerEnvelope, error) {

	lURI := fmt.Sprintf("%v/layers/%v?vulnerabilities", uri, id)
	response, err := http.Get(lURI)
	if err != nil {
		return v1.LayerEnvelope{}, fmt.Errorf("analysing layer %v: %v", id, err)
	}
	defer response.Body.Close()

	var analysis v1.LayerEnvelope
	err = json.NewDecoder(response.Body).Decode(&analysis)
	if err != nil {
		return v1.LayerEnvelope{}, fmt.Errorf("reading layer analysis: %v", err)
	}
	if response.StatusCode != 200 {
		//TODO(jgsqware): should I show reponse body in case of error?
		return v1.LayerEnvelope{}, fmt.Errorf("receiving http error: %d", response.StatusCode)
	}

	return analysis, nil
}
