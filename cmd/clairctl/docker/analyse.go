package docker

import (
	"github.com/Sirupsen/logrus"
	"github.com/coreos/clair/api/v1"
	"github.com/coreos/clair/cmd/clairctl/clair"
	"github.com/coreos/clair/cmd/clairctl/xstrings"
)

//Analyze return Clair Image analysis
func Analyze(image Image) clair.ImageAnalysis {
	c := len(image.FsLayers)
	res := []v1.LayerEnvelope{}

	for i := range image.FsLayers {
		l := image.FsLayers[c-i-1].BlobSum
		lShort := xstrings.Substr(l, 0, 12)

		if a, err := clair.Analyze(l); err != nil {
			logrus.Infof("analysing layer [%v] %d/%d: %v", lShort, i+1, c, err)
		} else {
			logrus.Infof("analysing layer [%v] %d/%d", lShort, i+1, c)
			res = append(res, a)
		}
	}
	return clair.ImageAnalysis{
		Registry:  xstrings.TrimPrefixSuffix(image.Registry, "http://", "/v2"),
		ImageName: image.Name,
		Tag:       image.Tag,
		Layers:    res,
	}
}
