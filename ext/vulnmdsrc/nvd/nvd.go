// Copyright 2017 clair authors
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

// Package nvd implements a vulnerability metadata appender using the NIST NVD
// database.
package nvd

import (
	"bufio"
	"compress/gzip"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/vulnmdsrc"
	"github.com/coreos/clair/pkg/commonerr"
)

const (
	dataFeedURL     string = "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%s.xml.gz"
	dataFeedMetaURL string = "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%s.meta"

	appenderName string = "NVD"

	logDataFeedName string = "data feed name"
)

type appender struct {
	localPath      string
	dataFeedHashes map[string]string
	metadata       map[string]NVDMetadata
}

type NVDMetadata struct {
	CVSSv2 NVDmetadataCVSSv2
}

type NVDmetadataCVSSv2 struct {
	Vectors string
	Score   float64
}

func init() {
	vulnmdsrc.RegisterAppender(appenderName, &appender{})
}

func (a *appender) BuildCache(datastore database.Datastore) error {
	var err error
	a.metadata = make(map[string]NVDMetadata)

	// Init if necessary.
	if a.localPath == "" {
		// Create a temporary folder to store the NVD data and create hashes struct.
		if a.localPath, err = ioutil.TempDir(os.TempDir(), "nvd-data"); err != nil {
			return commonerr.ErrFilesystem
		}

		a.dataFeedHashes = make(map[string]string)
	}

	// Get data feeds.
	dataFeedReaders, dataFeedHashes, err := getDataFeeds(a.dataFeedHashes, a.localPath)
	if err != nil {
		return err
	}
	a.dataFeedHashes = dataFeedHashes

	// Parse data feeds.
	for dataFeedName, dataFeedReader := range dataFeedReaders {
		var nvd nvd
		if err = xml.NewDecoder(dataFeedReader).Decode(&nvd); err != nil {
			log.WithError(err).WithField(logDataFeedName, dataFeedName).Error("could not decode NVD data feed")
			return commonerr.ErrCouldNotParse
		}

		// For each entry of this data feed:
		for _, nvdEntry := range nvd.Entries {
			// Create metadata entry.
			if metadata := nvdEntry.Metadata(); metadata != nil {
				a.metadata[nvdEntry.Name] = *metadata
			}
		}

		dataFeedReader.Close()
	}

	return nil
}

func (a *appender) Append(vulnName string, appendFunc vulnmdsrc.AppendFunc) error {
	if nvdMetadata, ok := a.metadata[vulnName]; ok {
		appendFunc(appenderName, nvdMetadata, SeverityFromCVSS(nvdMetadata.CVSSv2.Score))
	}

	return nil
}

func (a *appender) PurgeCache() {
	a.metadata = nil
}

func (a *appender) Clean() {
	os.RemoveAll(a.localPath)
}

func getDataFeeds(dataFeedHashes map[string]string, localPath string) (map[string]NestedReadCloser, map[string]string, error) {
	var dataFeedNames []string
	for y := 2002; y <= time.Now().Year(); y++ {
		dataFeedNames = append(dataFeedNames, strconv.Itoa(y))
	}

	// Get hashes for these feeds.
	for _, dataFeedName := range dataFeedNames {
		hash, err := getHashFromMetaURL(fmt.Sprintf(dataFeedMetaURL, dataFeedName))
		if err != nil {
			log.WithError(err).WithField(logDataFeedName, dataFeedName).Warning("could not get NVD data feed hash")

			// It's not a big deal, no need interrupt, we're just going to download it again then.
			continue
		}

		dataFeedHashes[dataFeedName] = hash
	}

	// Create io.Reader for every data feed.
	dataFeedReaders := make(map[string]NestedReadCloser)
	for _, dataFeedName := range dataFeedNames {
		fileName := localPath + dataFeedName + ".xml"

		if h, ok := dataFeedHashes[dataFeedName]; ok && h == dataFeedHashes[dataFeedName] {
			// The hash is known, the disk should contains the feed. Try to read from it.
			if localPath != "" {
				if f, err := os.Open(fileName); err == nil {
					dataFeedReaders[dataFeedName] = NestedReadCloser{
						Reader:            f,
						NestedReadClosers: []io.ReadCloser{f},
					}
					continue
				}
			}

			// Download data feed.
			r, err := http.Get(fmt.Sprintf(dataFeedURL, dataFeedName))
			if err != nil {
				log.WithError(err).WithField(logDataFeedName, dataFeedName).Error("could not download NVD data feed")
				return dataFeedReaders, dataFeedHashes, commonerr.ErrCouldNotDownload
			}

			// Un-gzip it.
			gr, err := gzip.NewReader(r.Body)
			if err != nil {
				log.WithError(err).WithField(logDataFeedName, dataFeedName).Error("could not read NVD data feed")
				return dataFeedReaders, dataFeedHashes, commonerr.ErrCouldNotDownload
			}

			// Store it to a file at the same time if possible.
			if f, err := os.Create(fileName); err == nil {
				nrc := NestedReadCloser{
					Reader:            io.TeeReader(gr, f),
					NestedReadClosers: []io.ReadCloser{r.Body, gr, f},
				}
				dataFeedReaders[dataFeedName] = nrc
			} else {
				nrc := NestedReadCloser{
					Reader:            gr,
					NestedReadClosers: []io.ReadCloser{gr, r.Body},
				}
				dataFeedReaders[dataFeedName] = nrc

				log.WithError(err).Warning("could not store NVD data feed to filesystem")
			}
		}
	}

	return dataFeedReaders, dataFeedHashes, nil
}

func getHashFromMetaURL(metaURL string) (string, error) {
	r, err := http.Get(metaURL)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()

	scanner := bufio.NewScanner(r.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "sha256:") {
			return strings.TrimPrefix(line, "sha256:"), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", errors.New("invalid .meta file format")
}

// SeverityFromCVSS converts the CVSS Score (0.0 - 10.0) into a
// database.Severity following the qualitative rating scale available in the
// CVSS v3.0 specification (https://www.first.org/cvss/specification-document),
// Table 14.
//
// The Negligible level is set for CVSS scores between [0, 1), replacing the
// specified None level, originally used for a score of 0.
func SeverityFromCVSS(score float64) database.Severity {
	switch {
	case score < 1.0:
		return database.NegligibleSeverity
	case score < 3.9:
		return database.LowSeverity
	case score < 6.9:
		return database.MediumSeverity
	case score < 8.9:
		return database.HighSeverity
	case score <= 10:
		return database.CriticalSeverity
	}
	return database.UnknownSeverity
}
