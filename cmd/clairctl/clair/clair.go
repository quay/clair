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
var healthPort int

//Report Reporting Config value
var Report ReportConfig

//VulnerabiliesCounts Total count of vulnerabilities by type
type VulnerabiliesCounts map[types.Priority]int

//Total return to total of Vulnerabilities
func (v VulnerabiliesCounts) Total() int {
	var c int
	for _, count := range v {
		c += count
	}
	return c
}

//Count return count of severities in Vulnerabilities
func (v VulnerabiliesCounts) Count(severity string) int {
	return v[types.Priority(severity)]
}

//RelativeCount get the percentage of vulnerabilities of a severity
func (v VulnerabiliesCounts) RelativeCount(severity string) float64 {
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
func (imageAnalysis ImageAnalysis) CountVulnerabilities(l v1.Layer) int {
	count := 0
	for _, f := range l.Features {
		count += len(f.Vulnerabilities)
	}
	return count
}

// CountAllVulnerabilities Total count of vulnerabilities
func (imageAnalysis ImageAnalysis) CountAllVulnerabilities() VulnerabiliesCounts {
	result := make(VulnerabiliesCounts)

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

type VulnerabilityWithFeature struct {
	v1.Vulnerability
	Feature string
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

func (imageAnalysis ImageAnalysis) ShortName(l v1.Layer) string {
	return xstrings.Substr(l.Name, 0, 12)
}

//Config configure Clair from configFile
func Config() {
	fmtURI(viper.GetString("clair.uri"), viper.GetInt("clair.port"))
	healthPort = viper.GetInt("clair.healthPort")
	Report.Path = viper.GetString("clair.report.path")
	Report.Format = viper.GetString("clair.report.format")
}
