package clair

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/coreos/clair/utils/types"
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

	fmt.Println(os.TempDir() + "/clairctl-html-report.html")

	err = ioutil.WriteFile(os.TempDir()+"/clairctl-html-report.html", []byte(html), 0700)
	if err != nil {
		log.Fatal(err)
	}
}

func TestInvertedPriorities(t *testing.T) {
	expected := []types.Priority{types.Defcon1, types.Critical, types.High, types.Medium, types.Low, types.Negligible, types.Unknown}
	ip := invertedPriorities()
	fmt.Printf("%v - %v", len(expected), len(ip))
	for i, v := range ip {
		if v != expected[i] {
			t.Errorf("Expecting %v, got %v", expected, ip)
		}
	}
}
