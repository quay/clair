package clair

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/coreos/clair/api/v1"
	"github.com/coreos/clair/utils/types"
)

//execute go generate ./clair
//go:generate go-bindata -pkg clair -o templates.go templates/...

//ReportConfig  Reporting configuration
type ReportConfig struct {
	Path   string
	Format string
}

//ReportAsHTML report analysis as HTML
func ReportAsHTML(analyzes ImageAnalysis) (string, error) {
	asset, err := Asset("templates/analysis-template.html")
	if err != nil {
		return "", fmt.Errorf("accessing template: %v", err)
	}

	funcs := template.FuncMap{
		"vulnerabilities":       vulnerabilities,
		"sortedVulnerabilities": SortedVulnerabilities,
	}

	templte := template.Must(template.New("analysis-template").Funcs(funcs).Parse(string(asset)))

	var doc bytes.Buffer
	err = templte.Execute(&doc, analyzes)
	if err != nil {
		return "", fmt.Errorf("rendering HTML report: %v", err)
	}
	return doc.String(), nil
}

func invertedPriorities() []types.Priority {
	ip := make([]types.Priority, len(types.Priorities))
	for i, j := 0, len(types.Priorities)-1; i <= j; i, j = i+1, j-1 {
		ip[i], ip[j] = types.Priorities[j], types.Priorities[i]
	}
	return ip

}

//Vulnerabilities return a list a vulnerabilities
func vulnerabilities(imageAnalysis ImageAnalysis) map[types.Priority][]vulnerabilityWithFeature {

	result := make(map[types.Priority][]vulnerabilityWithFeature)

	l := imageAnalysis.Layers[len(imageAnalysis.Layers)-1]
	for _, f := range l.Layer.Features {
		for _, v := range f.Vulnerabilities {

			result[types.Priority(v.Severity)] = append(result[types.Priority(v.Severity)], vulnerabilityWithFeature{Vulnerability: v, Feature: f.Name + ":" + f.Version})
		}
	}

	return result
}

// SortedVulnerabilities get all vulnerabilities sorted by Severity
func SortedVulnerabilities(imageAnalysis ImageAnalysis) []v1.Feature {
	features := []v1.Feature{}

	l := imageAnalysis.Layers[len(imageAnalysis.Layers)-1]

	for _, f := range l.Layer.Features {
		if len(f.Vulnerabilities) > 0 {
			vulnerabilities := []v1.Vulnerability{}
			for _, p := range invertedPriorities() {
				for _, v := range f.Vulnerabilities {
					if types.Priority(v.Severity) == p {
						vulnerabilities = append(vulnerabilities, v)
					}
				}
			}
			nf := f
			nf.Vulnerabilities = vulnerabilities
			features = append(features, nf)
		}
	}

	return features
}
