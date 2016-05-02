package clair

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"testing"
  "fmt"
)

func TestReportAsHtml(t *testing.T) {
	var analysis ImageAnalysis
	err := json.Unmarshal([]byte(getSampleAnalysis()), &analysis)

	if err != nil {
		t.Errorf("Failing with error: %v", err)
	}

	html, err := ReportAsHTML(analysis)
	if err != nil {
		log.Fatal(err)
	}
  
  fmt.Println(os.TempDir()+"/hyperclair-html-report.html")
  
	err = ioutil.WriteFile(os.TempDir()+"/hyperclair-html-report.html", []byte(html), 0700)
	if err != nil {
		log.Fatal(err)
	}
}
