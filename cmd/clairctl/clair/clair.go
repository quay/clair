package clair

import (
	"math"
	"strconv"
	"strings"

	"github.com/coreos/clair/api/v1"
	"github.com/coreos/clair/cmd/clairctl/xstrings"
	"github.com/coreos/clair/utils/types"
	"github.com/spf13/viper"
)

var uri string
var healthURI string

//Report Reporting Config value
var Report ReportConfig

//VulnerabiliesCounts Total count of vulnerabilities by type
type vulnerabiliesCounts map[types.Priority]int

//Total return to total of Vulnerabilities
func (v vulnerabiliesCounts) Total() int {
	var c int
	for _, count := range v {
		c += count
	}
	return c
}

//Count return count of severities in Vulnerabilities
func (v vulnerabiliesCounts) Count(severity string) int {
	return v[types.Priority(severity)]
}

//RelativeCount get the percentage of vulnerabilities of a severity
func (v vulnerabiliesCounts) RelativeCount(severity string) float64 {
	count := v[types.Priority(severity)]
	result := float64(count) / float64(v.Total()) * 100
	return math.Ceil(result*100) / 100
}

//ImageAnalysis Full image analysis
type ImageAnalysis struct {
	Registry, ImageName, Tag string
	Layers                   []v1.LayerEnvelope
}

func (imageAnalysis ImageAnalysis) String() string {
	return imageAnalysis.Registry + "/" + imageAnalysis.ImageName + ":" + imageAnalysis.Tag
}

// CountVulnerabilities counts all image vulnerability
func (imageAnalysis ImageAnalysis) countVulnerabilities(l v1.Layer) int {
	count := 0
	for _, f := range l.Features {
		count += len(f.Vulnerabilities)
	}
	return count
}

// CountAllVulnerabilities Total count of vulnerabilities
func (imageAnalysis ImageAnalysis) CountAllVulnerabilities() vulnerabiliesCounts {
	result := make(vulnerabiliesCounts)

	l := imageAnalysis.Layers[len(imageAnalysis.Layers)-1]

	for _, f := range l.Layer.Features {

		for _, v := range f.Vulnerabilities {
			result[types.Priority(v.Severity)]++
		}
	}

	return result
}

//LastLayer return the last layer of ImageAnalysis
func (imageAnalysis ImageAnalysis) LastLayer() *v1.Layer {
	return imageAnalysis.Layers[len(imageAnalysis.Layers)-1].Layer
}

type vulnerabilityWithFeature struct {
	v1.Vulnerability
	Feature string
}

func fmtURI(u string, port int) string {

	if port != 0 {
		u += ":" + strconv.Itoa(port)
	}
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		u = "http://" + u
	}

	return u
}

func (imageAnalysis ImageAnalysis) ShortName(l v1.Layer) string {
	return xstrings.Substr(l.Name, 0, 12)
}

//Config configure Clair from configFile
func Config() {
	uri = fmtURI(viper.GetString("clair.uri"), viper.GetInt("clair.port")) + "/v1"
	healthURI = fmtURI(viper.GetString("clair.uri"), viper.GetInt("clair.healthPort")) + "/health"
	Report.Path = viper.GetString("clair.report.path")
	Report.Format = viper.GetString("clair.report.format")
}
