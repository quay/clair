package main

import (
	"io"
	"path"
	"text/tabwriter"
	"text/template"
)

var _ Formatter = (*textFormatter)(nil)

// TextFormatter uses a custom text template and a tabwriter to present columnar
// output.
type textFormatter struct {
	tmpl *template.Template
	w    *tabwriter.Writer
	io.Closer
}

var funcmap = template.FuncMap{
	"base": path.Base,
}

func newTextFormatter(w io.WriteCloser) (*textFormatter, error) {
	tmpl, err := template.New("report").Funcs(funcmap).Parse(tabwriterTmpl)
	if err != nil {
		return nil, err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 1, ' ', 0)
	r := textFormatter{
		tmpl:   tmpl,
		w:      tw,
		Closer: w,
	}
	return &r, nil
}

const tabwriterTmpl = `
{{- define "ok" -}}
{{base .Name}}	ok
{{end}}
{{- define "err" -}}
{{base .Name}}	error	{{.Err}}
{{end}}
{{- define "found" -}}
{{with $r := .}}{{range $id, $v := .Report.PackageVulnerabilities}}{{range $d := $v -}}
{{base $r.Name}}	found	{{with index $r.Report.Packages $id}}{{.Name}}	{{.Version}}{{end}}
	{{- with index $r.Report.Vulnerabilities $d}}	{{.Name}}
	{{- with .FixedInVersion}}	(fixed: {{.}}){{end}}{{end}}
{{end}}{{end}}{{end}}{{end}}
{{- /* The following is the actual bit of the template that runs per item. */ -}}
{{if .Err}}{{template "err" .}}
{{- else if ne (len .Report.PackageVulnerabilities) 0}}{{template "found" .}}
{{- else}}{{template "ok" .}}
{{- end}}`

func (f *textFormatter) Format(r *Result) error {
	defer f.w.Flush()
	return f.tmpl.Execute(f.w, r)
}
