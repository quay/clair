// Copyright 2020 clair authors
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

package contentmanifest

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
	"time"

	"github.com/quay/clair/v3/pkg/httputil"
	log "github.com/sirupsen/logrus"
)

// LocalUpdaterJob periodically updates mapping file and store it in local storage
type LocalUpdaterJob struct {
	LocalPath string
	URL       string

	lastUpdateDate  time.Time
	lastHeaderQuery time.Time

	mappingFileMutex sync.Mutex
	updaterMutex     sync.Mutex
}

// NewLocalUpdaterJob creates new LocalUpdaterJob
func NewLocalUpdaterJob(localPath string, url string) *LocalUpdaterJob {
	updater := LocalUpdaterJob{
		LocalPath:        localPath,
		URL:              url,
		lastUpdateDate:   time.Time{},
		lastHeaderQuery:  time.Time{},
		mappingFileMutex: sync.Mutex{},
		updaterMutex:     sync.Mutex{},
	}
	return &updater
}

// Get translate repositories into CPEs using a mapping file
func (updater *LocalUpdaterJob) Get(repositories []string) ([]string, error) {
	updater.mappingFileMutex.Lock()
	defer updater.mappingFileMutex.Unlock()
	f, err := os.Open(updater.LocalPath)
	if err != nil {
		return []string{}, err
	}
	defer f.Close()

	mappingContent := MappingFile{}
	err = json.NewDecoder(f).Decode(&mappingContent)
	if err != nil {
		return []string{}, err
	}
	cpes := []string{}
	for _, repo := range repositories {
		if repoCPEs, ok := mappingContent.Data[repo]; ok {
			for _, cpe := range repoCPEs.CPEs {
				cpes = appendUnique(cpes, cpe)
			}
		} else {
			log.WithField("repository", repo).Debug("The repository is not present in a mapping file")
		}
	}
	return cpes, nil
}

// Update fetches mapping file using HTTP and store it locally in regular intervals
func (updater *LocalUpdaterJob) Update() error {
	updater.updaterMutex.Lock()
	defer updater.updaterMutex.Unlock()
	if updater.shouldBeUpdated() {
		log.Info("The repo2cpe mapping has newer version. Updating...")
		data, lastModified, err := updater.fetch()
		if err != nil {
			return err
		}
		err = updater.store(data)
		if err != nil {
			return err
		}
		log.WithField("path", updater.LocalPath).Info("Repo-CPE mapping file has been successfully updated")
		if lastModified != "" {
			lastModifiedDate, err := time.Parse(time.RFC1123, lastModified)
			if err != nil {
				log.WithField("lastUpdateDate", updater.lastUpdateDate).WithError(err).Error("Failed to parse lastUpdateDate")
				return err
			}
			// update local timestamp with latest date
			updater.lastUpdateDate = lastModifiedDate
		}
	}
	return nil
}

func (updater *LocalUpdaterJob) shouldBeUpdated() bool {
	if time.Now().Add(-8 * time.Hour).Before(updater.lastUpdateDate) {
		// mapping has been updated in past 8 hours
		// no need to query file headers
		log.Debug("The repo2cpe has been updated in past 8 hours. Skipping...")
		return false
	}
	// if it is more than 10 hours let's check file last-modified every 15 minutes
	if time.Now().Add(-15 * time.Minute).Before(updater.lastHeaderQuery) {
		// last header query has been done less than 15 minutes ago
		return false
	}
	// mapping file was updated more then 10 hours ago..
	// Let's check whether header has changed
	log.WithField("url", updater.URL).Debug("Fetching repo2cpe last-modified")
	resp, err := httputil.HeadWithUserAgent(updater.URL)
	if err != nil {
		return true
	}
	if !httputil.Status2xx(resp) {
		log.WithFields(log.Fields{
			"code":   resp.StatusCode,
			"url":    updater.URL,
			"method": "HEAD",
		}).Warning("Got non 2xx code from repo2cpe mapping")
		return true
	}
	lastModified := resp.Header.Get("last-modified")
	lastModifiedTime, err := time.Parse(time.RFC1123, lastModified)
	if err != nil {
		return true
	}
	updater.lastHeaderQuery = time.Now()
	return lastModifiedTime.After(updater.lastUpdateDate)
}

func (updater *LocalUpdaterJob) fetch() ([]byte, string, error) {
	log.WithField("url", updater.URL).Info("Fetching repo2cpe mapping file")
	resp, err := httputil.GetWithUserAgent(updater.URL)
	if err != nil {
		return []byte{}, "", err
	}
	defer resp.Body.Close()
	if !httputil.Status2xx(resp) {
		log.WithFields(log.Fields{
			"code":   resp.StatusCode,
			"url":    updater.URL,
			"method": "GET",
		}).Warning("Got non 2xx code from repo2cpe mapping")
		return []byte{}, "", fmt.Errorf("Got non 2xx code from repo2cpe mapping: [GET] %d - %s", resp.StatusCode, updater.URL)
	}
	lastModified := resp.Header.Get("last-modified")
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, "", err
	}
	return body, lastModified, nil
}

func (updater *LocalUpdaterJob) store(data []byte) error {
	updater.mappingFileMutex.Lock()
	defer updater.mappingFileMutex.Unlock()
	f, err := os.OpenFile(updater.LocalPath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	if err != nil {
		return err
	}
	return nil
}

func appendUnique(items []string, item string) []string {
	for _, value := range items {
		if value == item {
			return items
		}
	}
	items = append(items, item)
	return items
}
