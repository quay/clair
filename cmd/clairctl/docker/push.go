package docker

import (
	"fmt"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/coreos/clair/api/v1"
	"github.com/coreos/clair/cmd/clairctl/clair"
	"github.com/coreos/clair/cmd/clairctl/config"
	"github.com/coreos/clair/cmd/clairctl/xstrings"
)

var registryMapping map[string]string

//Push image to Clair for analysis
func Push(image Image) error {
	layerCount := len(image.FsLayers)

	parentID := ""

	if layerCount == 0 {
		logrus.Warningln("there is no layer to push")
	}
	localIP, err := config.LocalServerIP()
	if err != nil {
		return err
	}
	hURL := fmt.Sprintf("http://%v/v2", localIP)
	if IsLocal {
		hURL += "/local"
		logrus.Infof("using %v as local url", hURL)
	}

	for index, layer := range image.FsLayers {
		lUID := xstrings.Substr(layer.BlobSum, 0, 12)
		logrus.Infof("Pushing Layer %d/%d [%v]", index+1, layerCount, lUID)

		insertRegistryMapping(layer.BlobSum, image.Registry)
		payload := v1.LayerEnvelope{Layer: &v1.Layer{
			Name:       layer.BlobSum,
			Path:       image.BlobsURI(layer.BlobSum),
			ParentName: parentID,
			Format:     "Docker",
		}}

		//FIXME Update to TLS
		if IsLocal {
			payload.Layer.Name = layer.History
			payload.Layer.Path += "/layer.tar"
		}
		payload.Layer.Path = strings.Replace(payload.Layer.Path, image.Registry, hURL, 1)
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
	if IsLocal {
		if err := cleanLocal(); err != nil {
			return err
		}
	}
	return nil
}

func insertRegistryMapping(layerDigest string, registryURI string) {
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
