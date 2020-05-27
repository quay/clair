// Copyright 2018 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mitre

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestMitreParser(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename))

	dataFilePath := filepath.Join(path, "/testdata/test_good.xml")
	testData, err := os.Open(dataFilePath)
	if err != nil {
		t.Fatalf("Error opening %q: %v", dataFilePath, err)
	}
	defer testData.Close()

	a := &appender{}
	a.metadata = make(map[string]MitreMetadata)

	err = a.parseDataFeed(testData)

	if err != nil {
		t.Fatalf("Error parsing %q: %v", dataFilePath, err)
	}

	// We expect there to be 2 CVEs in the list
	// The ones without references are skipped
	if l := len(a.metadata); l != 2 {
		t.Errorf("Metadata contains %d CVEs. It should be 2.", l)
	}

	// Check that the CVEs without references are not in the map
	noReferencesCVEs := [2]string{"CVE-2000-0003", "CVE-2000-0004"}
	for _, cve := range noReferencesCVEs {
		if foundMetadata, ok := a.metadata[cve]; ok {
			t.Errorf(`Found metadata "%s" for %s which has no references.`, foundMetadata.ReferenceURLs, cve)
		}
	}

	// Check metadata for CVEs with reference against expected output
	var expected [2]MitreMetadata
	expected[0] = MitreMetadata{
		ReferenceURLs: []string{
			"https://www.example.com/index.html?id=3333",
			"https://www.example.net/2001/vuln-0012",
		},
	}
	expected[1] = MitreMetadata{
		ReferenceURLs: []string{
			"https://www.example.org/some/path/index.html?id=5222",
		},
	}
	for idx, md := range expected {
		cve := fmt.Sprintf("CVE-2001-%04d", idx+1)
		if found, ok := a.metadata[cve]; !ok {
			if ok {
				if len(found.ReferenceURLs) != len(md.ReferenceURLs) {
					t.Errorf("Did not get expected number of reference URLs for %s. (%d != %d)", cve, len(found.ReferenceURLs), len(md.ReferenceURLs))
				} else {
					for fi, fs := range found.ReferenceURLs {
						if fs != md.ReferenceURLs[fi] {
							t.Errorf("Metadata strings for %s were not as expected. (%s != %s)", cve, fs, md.ReferenceURLs[fi])
						}
					}
				}

			} else {
				t.Errorf("Did not find any metadata for %s.", cve)
			}
		}
	}
}

func TestMitreParserErrors(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename))

	dataFilePath := filepath.Join(path, "/testdata/test_bad.xml")
	testData, err := os.Open(dataFilePath)
	if err != nil {
		t.Fatalf("Error opening %q: %v", dataFilePath, err)
	}
	defer testData.Close()

	a := &appender{}
	a.metadata = make(map[string]MitreMetadata)

	err = a.parseDataFeed(testData)
	if err == nil {
		t.Fatalf("Expected error parsing NVD data file: %q", dataFilePath)
	}
}

func TestExtractTimestampFromIndexPage(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename))

	indexFilePath := filepath.Join(path, "/testdata/test_index.html")
	testData, err := os.Open(indexFilePath)
	if err != nil {
		t.Fatalf("Error opening %q: %v", indexFilePath, err)
	}
	defer testData.Close()

	if tstamp, err := extractTimestampFromIndexPage(testData); (err != nil) || (tstamp != "2019-01-17") {
		t.Errorf("The timestamp extracted from the index page was wrong. Expected: 2019-01-17. Found: %s", tstamp)
	}
}

func TestDownloadDataFeed(t *testing.T) {
	payload := "success"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/2006.xml" {
			fmt.Fprint(w, payload)
		} else {
			w.WriteHeader(404)
		}
	}))
	tmpdir, err := ioutil.TempDir(os.TempDir(), "mitre-tests")
	if err != nil {
		t.Errorf("Could not create temporary data driectory to download feed to. (%s)", err)
	}
	fname := tmpdir + "/dlTest.xml"

	// successful download
	err = downloadFeed("2006", fname, fmt.Sprint(server.URL+`/%s.xml`))
	if err != nil {
		t.Errorf("Data feed download failed. (%s)", err)
	}
	tmpfile, err := os.Open(fname)
	if err != nil {
		t.Errorf("Could not open temporary file feed was downloaded to. (%s)", err)
	}
	contents, err := ioutil.ReadAll(tmpfile)
	if err != nil {
		t.Errorf("Could not read feed data from temporary file. (%s)", err)
	}
	if string(contents) != payload {
		t.Errorf(`Feed's contents were not as expected. ("%s" != "%s")`, contents, payload)
	}

	// file not found on server
	err = downloadFeed("2007", fname, fmt.Sprint(server.URL+`/%s.xml`))
	if err == nil {
		t.Errorf("Download should have failed with 404 but passed.")
	}

	// destination on disk does not exist
	dirname := os.TempDir() + "/does/not"
	fname = dirname + "/exist"
	if _, err := os.Stat(dirname); os.IsExist(err) {
		t.Errorf("Directory %s is expected to not exist when running this test. Please delete it and re-run the test.", tmpdir)
	}
	err = downloadFeed("2006", fname, fmt.Sprint(server.URL+`/%s.xml`))
	if err == nil {
		t.Errorf("No error returned but target file could not be created.")
	}
}

func TestGetTimestampFromIndexPage(t *testing.T) {
	tstamp := "2019-01-24"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tstamp": // correct formatting
			fmt.Fprintf(w, "CVE downloads data last generated:\n%s", tstamp)
		case "/badtstamp": // not the formatting we expect
			fmt.Fprintf(w, "CVE downloads data available: %s", tstamp)
		default: // defaulting to "file not found"
			w.WriteHeader(404)
		}
	}))

	// successful retrieval
	ts, err := getTimestampFromIndexPage(server.URL + "/tstamp")
	if err != nil {
		t.Errorf("Could not retrieve index page. (%s)", err)
	} else if ts != tstamp {
		t.Errorf(`Retrieved timestamp "%s" was not as expected (%s).`, ts, tstamp)
	}

	// broken timestamp
	_, err = getTimestampFromIndexPage(server.URL + "/badtstamp")
	if err == nil {
		t.Errorf("Timestamp wasn't extracted but no error returned.")
	}

	// file not found on server
	_, err = getTimestampFromIndexPage(server.URL + "/incorrecturl")
	if err == nil {
		t.Errorf("Timestamp URL was incorrect but no error was returned.")
	}
}

func TestGetDataFeeds(t *testing.T) {
	tstamp := "2019-01-24"
	xmlUrl := regexp.MustCompile(`^/(1999|2\d{3})\.xml`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log(r.URL.Path)
		if xmlUrl.MatchString(r.URL.Path) {
			fmt.Fprint(w, "<xml>")
			return
		}
		switch r.URL.Path {
		case "/tstamp": // correct formatting
			fmt.Fprintf(w, "CVE downloads data last generated:\n%s", tstamp)
		default: // defaulting to "file not found"
			w.WriteHeader(404)
		}
	}))
	tstampUrl := server.URL + "/tstamp"
	feedUrlTmpl := server.URL + "/%s.xml"
	dataFeedTimestamps := make(map[string]string)
	tmpdir, err := makeTmpdirWithFile(tstamp, "2005")
	if err != nil {
		t.Fatalf("Could not create temporary directory. (%s)", err)
	}
	dataFeedTimestamps = make(map[string]string)
	feeds, feedts, err := getDataFeeds(dataFeedTimestamps, tmpdir, tstampUrl, feedUrlTmpl)

	currentYear := time.Now().Year()
	noOfExpectedFeeds := currentYear + 1 - 1999
	if len(feeds) != noOfExpectedFeeds {
		t.Errorf("No of feeds on disk (%d) does not match expected (%d).", len(feeds), noOfExpectedFeeds)
	}
	if len(feedts) != noOfExpectedFeeds {
		t.Errorf("No of returned timestamps (%d) does not match expected (%d).", len(feeds), noOfExpectedFeeds)
	}
	expectedTimestampKeyFormat := regexp.MustCompile(`(1999|2\d{3})-` + tstamp)
	for k, v := range feedts {
		if !expectedTimestampKeyFormat.MatchString(k) {
			t.Errorf(`Key "%s" in timestamp map does not have the expected format.`, k)
		}
		if v != tstamp {
			t.Errorf(`Unexpected timestamp "%s" in timestamp map.`, v)
		}
	}

	expectedFeedNameFormat := regexp.MustCompile(`/(1999|2\d{3})\.xml$`)
	for i := 1999; i <= currentYear; i++ {
		yearStr := strconv.Itoa(i)
		if feedFile, ok := feeds[yearStr]; !ok {
			t.Errorf(`Expected to find year "%s" in list but it didn't exist.`, yearStr)
		} else {
			if !expectedFeedNameFormat.MatchString(feedFile) {
				t.Errorf(`The feed's "%s" file name did not match the expected pattern.`, feedFile)
			}
			if feed, err := os.Open(feedFile); err != nil {
				t.Errorf(`Could not open returned feed file "%s". (%s)`, feedFile, err)
			} else {
				if feedXML, err := ioutil.ReadAll(feed); err != nil {
					t.Errorf(`Could not read stored XML for feed "%s". (%s)`, feedFile, err)
				} else {
					if string(feedXML) != "<xml>" {
						t.Errorf(`Feed XML "%s" was not the expected "<xml>".`, feedXML)
					}
				}
			}
		}
	}

	// feed download failure
	tmpdir, err = makeTmpdirWithFile(tstamp, "1999")
	if err != nil {
		t.Fatalf("Could not create temporary directory. (%s)", err)
	}
	// clear the map
	dataFeedTimestamps = make(map[string]string)
	feeds, feedts, err = getDataFeeds(dataFeedTimestamps, tmpdir, tstampUrl, server.URL+"/wrong/path/%s.xml")
	if err == nil {
		t.Error("Download of feeds did not fail as expected.")
	}
	if len(feeds) != 0 {
		t.Errorf("Got %d feeds despite download error.", len(feeds))
	}
	if len(feedts) != 0 {
		t.Errorf("Got %d feed timestamps despite download error.", len(feedts))
	}
}

func makeTmpdirWithFile(tstamp string, yearStr string) (string, error) {
	tmpdir, err := ioutil.TempDir(os.TempDir(), "mitre-data-tests")
	if err != nil {
		return "", fmt.Errorf("could not create directory to store feed data in. (%s)", err)
	}
	xmlFile := tmpdir + "/" + yearStr + "-" + tstamp + ".xml"
	f, err := os.Create(xmlFile)
	if err != nil {
		return "", fmt.Errorf(`could not create file "%s". (%s)`, xmlFile, err)
	} else {
		_, err := f.Write([]byte("<xml>"))
		if err != nil {
			return "", fmt.Errorf(`could not write to file "%s". (%s)`, xmlFile, err)
		}
		f.Close()
	}
	return tmpdir, nil
}
