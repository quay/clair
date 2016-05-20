package clair

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Sirupsen/logrus"
)

func getSampleAnalysis() []byte {
	file, err := ioutil.ReadFile("./samples/clair_report.json")

	if err != nil {
		logrus.Errorf("File error: %v\n", err)
	}

	return file
}

func newServer(httpStatus int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(httpStatus)
	}))
}

func TestIsHealthy(t *testing.T) {
	server := newServer(http.StatusOK)
	defer server.Close()
	healthURI = server.URL
	if h := IsHealthy(); !h {
		t.Errorf("IsHealthy() => %v, want %v", h, true)
	}
}

func TestIsNotHealthy(t *testing.T) {
	server := newServer(http.StatusInternalServerError)
	defer server.Close()
	uri = server.URL
	if h := IsHealthy(); h {
		t.Errorf("IsHealthy() => %v, want %v", h, true)
	}
}

func TestRelativeCount(t *testing.T) {
	var analysis ImageAnalysis
	err := json.Unmarshal([]byte(getSampleAnalysis()), &analysis)

	if err != nil {
		t.Errorf("Failing with error: %v", err)
	}

	vulnerabilitiesCount := allVulnerabilities(analysis)
	if vulnerabilitiesCount.RelativeCount("High") != 1.3 {
		t.Errorf("analysis.CountAllVulnerabilities().RelativeCount(\"High\") => %v, want 1.3", vulnerabilitiesCount.RelativeCount("High"))
	}

	if vulnerabilitiesCount.RelativeCount("Medium") != 23.38 {
		t.Errorf("analysis.CountAllVulnerabilities().RelativeCount(\"Medium\") => %v, want 23.38", vulnerabilitiesCount.RelativeCount("Medium"))
	}

	if vulnerabilitiesCount.RelativeCount("Low") != 74.03 {
		t.Errorf("analysis.CountAllVulnerabilities().RelativeCount(\"Low\") => %v, want 74.03", vulnerabilitiesCount.RelativeCount("Low"))
	}
}
