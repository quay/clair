package clair

import (
	"strconv"
	"strings"

	"github.com/coreos/clair/api/v1"
	"github.com/coreos/clair/cmd/clairclt/xstrings"
	"github.com/spf13/viper"
)

var uri string
var priority string
var healthPort int

//Report Reporting Config value
var Report ReportConfig

//ImageAnalysis Full image analysis
type ImageAnalysis struct {
	Registry  string
	ImageName string
	Tag       string
	Layers    []v1.LayerEnvelope
}

func (imageAnalysis ImageAnalysis) String() string {
	return imageAnalysis.Registry + "/" + imageAnalysis.ImageName + ":" + imageAnalysis.Tag
}

func (imageAnalysis ImageAnalysis) ShortName(l v1.Layer) string {
	return xstrings.Substr(l.Name, 0, 12)
}

func (imageAnalysis ImageAnalysis) CountVulnerabilities(l v1.Layer) int {
	count := 0
	for _, f := range l.Features {
		count += len(f.Vulnerabilities)
	}
	return count
}

type Vulnerability struct {
	Name, Severity, IntroduceBy, Description, Layer string
}

func (imageAnalysis ImageAnalysis) SortVulnerabilities() []Vulnerability {
	low := []Vulnerability{}
	medium := []Vulnerability{}
	high := []Vulnerability{}
	critical := []Vulnerability{}
	defcon1 := []Vulnerability{}

	for _, l := range imageAnalysis.Layers {
		for _, f := range l.Layer.Features {
			for _, v := range f.Vulnerabilities {
				nv := Vulnerability{
					Name:        v.Name,
					Severity:    v.Severity,
					IntroduceBy: f.Name + ":" + f.Version,
					Description: v.Description,
					Layer:       l.Layer.Name,
				}
				switch strings.ToLower(v.Severity) {
				case "low":
					low = append(low, nv)
				case "medium":
					medium = append(medium, nv)
				case "high":
					high = append(high, nv)
				case "critical":
					critical = append(critical, nv)
				case "defcon1":
					defcon1 = append(defcon1, nv)
				}
			}
		}
	}

	return append(defcon1, append(critical, append(high, append(medium, low...)...)...)...)
}

func fmtURI(u string, port int) {
	uri = u
	if port != 0 {
		uri += ":" + strconv.Itoa(port)
	}
	if !strings.HasSuffix(uri, "/v1") {
		uri += "/v1"
	}
	if !strings.HasPrefix(uri, "http://") && !strings.HasPrefix(uri, "https://") {
		uri = "http://" + uri
	}
}

//Config configure Clair from configFile
func Config() {
	fmtURI(viper.GetString("clair.uri"), viper.GetInt("clair.port"))
	priority = viper.GetString("clair.priority")
	healthPort = viper.GetInt("clair.healthPort")
	Report.Path = viper.GetString("clair.report.path")
	Report.Format = viper.GetString("clair.report.format")
}
