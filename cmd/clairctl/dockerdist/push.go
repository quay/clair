package dockerdist

import (
	"fmt"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/coreos/clair/api/v1"
	"github.com/coreos/clair/cmd/clairctl/clair"
	"github.com/coreos/clair/cmd/clairctl/config"
	"github.com/coreos/clair/cmd/clairctl/docker"
	"github.com/coreos/clair/cmd/clairctl/xstrings"
	"github.com/docker/distribution/manifest/schema1"
	"github.com/docker/docker/reference"
)

var registryMapping map[string]string

//Push image to Clair for analysis
func Push(image reference.Named, manifest schema1.SignedManifest) error {
	layerCount := len(manifest.FSLayers)

	parentID := ""

	if layerCount == 0 {
		logrus.Warningln("there is no layer to push")
	}
	localIP, err := config.LocalServerIP()
	if err != nil {
		return err
	}
	hURL := fmt.Sprintf("http://%v/v2", localIP)
	if docker.IsLocal {
		hURL = strings.Replace(hURL, "/v2", "/local", -1)
		logrus.Infof("using %v as local url", hURL)
	}

	for index, layer := range manifest.FSLayers {
		blobsum := layer.BlobSum.String()
		if docker.IsLocal {
			blobsum = strings.TrimPrefix(blobsum, "sha256:")
		}

		lUID := xstrings.Substr(blobsum, 0, 12)
		logrus.Infof("Pushing Layer %d/%d [%v]", index+1, layerCount, lUID)

		insertRegistryMapping(blobsum, image.Hostname())
		payload := v1.LayerEnvelope{Layer: &v1.Layer{
			Name:       blobsum,
			Path:       blobsURI(image.Hostname(), image.RemoteName(), blobsum),
			ParentName: parentID,
			Format:     "Docker",
		}}

		//FIXME Update to TLS
		if docker.IsLocal {

			payload.Layer.Path += "/layer.tar"
		}
		payload.Layer.Path = strings.Replace(payload.Layer.Path, image.Hostname(), hURL, 1)
		if err := clair.Push(payload); err != nil {
			logrus.Infof("adding layer %d/%d [%v]: %v", index+1, layerCount, lUID, err)
			if err != clair.ErrUnanalizedLayer {
				return err
			}
			parentID = ""
		} else {
			parentID = payload.Layer.Name
		}
	}
	if docker.IsLocal {
		if err := docker.CleanLocal(); err != nil {
			return err
		}
	}
	return nil
}

func blobsURI(registry string, name string, digest string) string {
	return strings.Join([]string{registry, name, "blobs", digest}, "/")
}

func insertRegistryMapping(layerDigest string, registryURI string) {
	if strings.Contains(registryURI, "docker") {
		registryURI = "https://" + registryURI + "/v2"

	} else {
		registryURI = "http://" + registryURI + "/v2"
	}
	logrus.Debugf("Saving %s[%s]", layerDigest, registryURI)
	registryMapping[layerDigest] = registryURI
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
