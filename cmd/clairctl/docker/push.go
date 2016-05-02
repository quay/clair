package docker

import (
	"fmt"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/coreos/clair/api/v1"
	"github.com/coreos/clair/cmd/clairctl/clair"
	"github.com/coreos/clair/cmd/clairctl/config"
	"github.com/coreos/clair/cmd/clairctl/database"
	"github.com/coreos/clair/cmd/clairctl/xstrings"
)

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

		database.InsertRegistryMapping(layer.BlobSum, image.Registry)
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
			if err != clair.OSNotSupported {
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
