package main

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"sync"
)

var _ Formatter = (*xmlFormatter)(nil)

// XmlFormatter is an attempt to create jUnit-compatible output.
type xmlFormatter struct {
	sync.Mutex
	enc *xml.Encoder
	c   io.Closer
	out junitOut
}

func (f *xmlFormatter) Reset(w io.WriteCloser) error {
	f.c = w
	io.WriteString(w, xml.Header)
	f.enc = xml.NewEncoder(w)
	return nil
}

func (f *xmlFormatter) Format(r *Result) error {
	var j junitTestsuite
	if err := j.Init(r); err != nil {
		return err
	}
	f.Lock()
	defer f.Unlock()
	f.out.Tests = append(f.out.Tests, &j)
	return nil
}

func (f *xmlFormatter) Close() error {
	defer f.c.Close()
	return f.enc.Encode(f.out)
}

type junitOut struct {
	XMLName xml.Name `xml:"testsuites"`
	Tests   []*junitTestsuite
}

type junitTestsuite struct {
	XMLName  xml.Name `xml:"testsuite"`
	Name     string   `xml:"name,attr"`
	NumTests int      `xml:"tests,attr"`
	Errors   int      `xml:"errors,attr"`
	Failures int      `xml:"failures,attr"`
	Props    struct {
		XMLName xml.Name `xml:"properties"`
		Props   []junitProp
	}
	Tests []junitTestcase
}

func (j *junitTestsuite) Init(r *Result) error {
	j.Name = r.Name
	j.Errors = 0
	j.Failures = 0
	j.NumTests = 0
	j.Props.Props = make([]junitProp, 1)
	j.Props.Props[0].Name = "manifest"
	j.Props.Props[0].Value = r.Report.Hash.String()

	if r.Err != nil {
		j.Tests = []junitTestcase{
			{Error: r.Err.Error()},
		}
		j.NumTests++
		j.Errors++
		return nil
	}

	j.Tests = make([]junitTestcase, len(r.Report.Packages))
	j.NumTests = len(r.Report.Packages)
	i := 0
	var b strings.Builder
	for pkgID, pkg := range r.Report.Packages {
		tc := &j.Tests[i]
		tc.Name = fmt.Sprintf("%s %s", pkg.Name, pkg.Version)
		vs, ok := r.Report.PackageVulnerabilities[pkgID]
		if ok {
			j.Failures++
			b.Reset()
			b.WriteString("Found the following vulnerabilities:")
			for _, vID := range vs {
				v := r.Report.Vulnerabilities[vID]
				b.WriteByte('\n')
				b.WriteByte('\t')
				b.WriteString(v.Name)
			}
			tc.Failure = b.String()
		}
		i++
	}
	return nil
}

type junitProp struct {
	XMLName xml.Name `xml:"property"`
	Name    string   `xml:"name,attr"`
	Value   string   `xml:"value,attr"`
}

type junitTestcase struct {
	XMLName xml.Name `xml:"testcase"`
	Name    string   `xml:"name,attr"`
	Error   string   `xml:"error,omitempty"`
	Failure string   `xml:"failure,omitempty"`
}
