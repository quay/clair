// Copyright 2019 clair authors
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

// Package mitre implements a vulnerability source updater using Mitre's CVE
// database
package mitre

import (
	"bufio"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/quay/clair/v3/database"
	"github.com/quay/clair/v3/ext/vulnmdsrc"
	"github.com/quay/clair/v3/pkg/commonerr"
	"github.com/quay/clair/v3/pkg/httputil"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/html/charset"
)

const (
	timestampURL    string = "https://cve.mitre.org/data/downloads/index.html"
	dataFeedURL     string = "https://cve.mitre.org/data/downloads/allitems-cvrf-year-%s.xml"
	appenderName    string = "mitre"
	logDataFeedName string = "data feed name"
)

var lastUpdate *regexp.Regexp

type appender struct {
	localPath      string
	dataFeedHashes map[string]string
	metadata       map[string]MitreMetadata
}

type MitreMetadata struct {
	ReferenceURLs []string
}

func init() {
	vulnmdsrc.RegisterAppender("mitre", &appender{})
	lastUpdate = regexp.MustCompile(`(?ms:^.*?CVE downloads data last generated:(?:\s*)(?:$.)?(\d{4}-\d{2}-\d{2}).*)`)
}

func (a *appender) BuildCache(datastore database.Datastore) error {
	var err error
	a.metadata = make(map[string]MitreMetadata)

	// Init if necessary.
	if a.localPath == "" {
		// Create a temporary folder to store the Mitre data and create hashes struct.
		if a.localPath, err = ioutil.TempDir(os.TempDir(), "mitre-data"); err != nil {
			return commonerr.ErrFilesystem
		}

		a.dataFeedHashes = make(map[string]string)
	}

	// Get data feeds.
	dataFeedReaders, dataFeedHashes, err := getDataFeeds(a.dataFeedHashes, a.localPath, timestampURL, dataFeedURL)
	if err != nil {
		return err
	}
	a.dataFeedHashes = dataFeedHashes

	// Parse data feeds.
	for dataFeedName, dataFileName := range dataFeedReaders {
		f, err := os.Open(dataFileName)
		if err != nil {
			log.WithError(err).WithField(logDataFeedName, dataFeedName).Error("could not open Mitre data file")
			return commonerr.ErrCouldNotParse
		}

		r := bufio.NewReader(f)
		if err := a.parseDataFeed(r); err != nil {
			log.WithError(err).WithField(logDataFeedName, dataFeedName).Error("could not parse Mitre data file")
			return err
		}
		f.Close()
	}

	return nil

}

func (a *appender) parseDataFeed(r io.Reader) error {
	var mitreDoc cvrfDoc

	d := xml.NewDecoder(r)
	d.CharsetReader = charset.NewReaderLabel
	if err := d.Decode(&mitreDoc); err != nil {
		return commonerr.ErrCouldNotParse
	}

	for _, vuln := range mitreDoc.Vulnerability {
		// Create metadata entry.
		if metadata := vuln.Metadata(); metadata != nil {
			a.metadata[vuln.Name()] = *metadata
		}
	}

	return nil
}

func (a *appender) Append(vulnName string, appendFunc vulnmdsrc.AppendFunc) error {
	if mitreMetadata, ok := a.metadata[vulnName]; ok {
		appendFunc(appenderName, mitreMetadata, database.UnknownSeverity)
	}

	return nil
}

func (a *appender) PurgeCache() {
	a.metadata = nil
}

func (a *appender) Clean() {
	err := os.RemoveAll(a.localPath)
	if err != nil {
		log.WithError(err).Warning("Could not remove temporary download path for Mitre data.")
	}
}

func getDataFeeds(dataFeedTimestamps map[string]string, localPath string, tsUrl string, dfUrlTemplate string) (map[string]string, map[string]string, error) {
	var dataFeedNames []string
	for y := 1999; y <= time.Now().Year(); y++ {
		dataFeedNames = append(dataFeedNames, strconv.Itoa(y))
	}

	// Get last update's timestamp
	tstamp := "" // default to "not found"
	retry := 3
	for retry > 0 {
		var err error
		tstamp, err = getTimestampFromIndexPage(tsUrl)
		if err != nil {
			log.WithError(err).Warning("could not get Mitre data feed update timestamp")

			// Retry a few times. The index page is much smaller than even just one of the data feeds.
			retry--
			continue
		}
		// download succeeded, so no need to retry
		retry = 0
	}
	// Create map containing the name and filename for every data feed.
	dataFeedReaders := make(map[string]string)
	for _, dataFeedName := range dataFeedNames {
		fileName := filepath.Join(localPath, fmt.Sprintf("%s.xml", dataFeedName))
		currentDataFeed := fmt.Sprintf("%s-%s", dataFeedName, tstamp)

		// If the correct file exists already, we do not need to download it again
		if _, ok := dataFeedTimestamps[currentDataFeed]; ok {
			if localPath != "" {
				if f, err := os.Open(fileName); err == nil {
					f.Close()
					dataFeedReaders[dataFeedName] = fileName
					continue
				}
			}
		}

		err := downloadFeed(dataFeedName, fileName, dfUrlTemplate)
		if err != nil {
			return dataFeedReaders, dataFeedTimestamps, err
		}
		dataFeedReaders[dataFeedName] = fileName
		dataFeedTimestamps[currentDataFeed] = tstamp
	}

	return dataFeedReaders, dataFeedTimestamps, nil
}

func downloadFeed(dataFeedName, fileName string, dfUrl string) error {
	// Download data feed.
	url := fmt.Sprintf(dfUrl, dataFeedName)
	r, err := httputil.GetWithUserAgent(url)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{logDataFeedName: dataFeedName, "URL": url}).Error("could not download Mitre data feed")
		return commonerr.ErrCouldNotDownload
	}
	defer r.Body.Close()

	if !httputil.Status2xx(r) {
		log.WithFields(log.Fields{"StatusCode": r.StatusCode, "DataFeedName": dataFeedName}).Error("failed to download Mitre data feed")
		return commonerr.ErrCouldNotDownload
	}

	// Store it to a file
	f, err := os.Create(fileName)
	if err != nil {
		log.WithError(err).WithField("Filename", fileName).Warning("could not create file for storing Mitre feed")
		return commonerr.ErrFilesystem
	}
	defer f.Close()

	_, err = io.Copy(f, r.Body)
	if err != nil {
		log.WithError(err).WithField("Filename", fileName).Warning("could not stream Mitre data feed to filesystem")
		return commonerr.ErrFilesystem
	}

	return nil
}

func getTimestampFromIndexPage(indexURL string) (string, error) {
	r, err := httputil.GetWithUserAgent(indexURL)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()

	if !httputil.Status2xx(r) {
		return "", errors.New(indexURL + " failed status code: " + string(r.StatusCode))
	}

	return extractTimestampFromIndexPage(r.Body)
}

func extractTimestampFromIndexPage(indexPage io.Reader) (string, error) {
	indexPageHtml, err := ioutil.ReadAll(indexPage)
	//log.WithField("HTML", string(indexPageHtml)).Info("downloaded index page.")
	if err != nil {
		return "", err
	}
	if lastUpdate.Match(indexPageHtml) {
		return string(lastUpdate.ReplaceAll(indexPageHtml, []byte(`$1`))[:]), nil
	}

	return "", errors.New("could not find date of last update in index page")
}
