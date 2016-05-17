package clair

import (
	"bytes"
	"fmt"
	"text/template"
)

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

	templte := template.Must(template.New("analysis-template").Parse(string(asset)))

	var doc bytes.Buffer
	err = templte.Execute(&doc, analyzes)
	if err != nil {
		return "", fmt.Errorf("rendering HTML report: %v", err)
	}
	return doc.String(), nil
}
