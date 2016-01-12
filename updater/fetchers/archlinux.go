// Copyright 2015, 2016 clair authors
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

package fetchers

import (
	"bufio"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/updater"
	cerrors "github.com/coreos/clair/utils/errors"
)

const (
	archLinuxCVEURL      = "https://wiki.archlinux.org/api.php?action=query&titles=CVE&format=txt&prop=revisions&rvlimit=1&rvprop=content"
	archlinuxUpdaterFlag = "archlinuxUpdater"
	tokensRegexp         = "{|}|CVF|PKG|Pkg|pkg|\\[|\\]"
)

type SecurityAdvisory struct {
	Name string
	URL  string
}

// ArchCVE represents a CVE for Arch Linux
type ArchCVE struct {
	CVEID           string
	Package         string
	DisclosureDate  string
	AffectedVersion string
	FixedInVersion  string
	ResponseTime    string
	Status          string
	ASAID           SecurityAdvisory
}

// ArchlinuxFetcher implements updater.Fetcher for the Archlinux CVE
// (See wiki : https://wiki.archlinux.org/index.php/CVE).
type ArchlinuxFetcher struct{}

func init() {
	updater.RegisterFetcher("archlinux", &ArchlinuxFetcher{})
}

// FetchUpdate fetches vulnerability updates from the Archlinux Security Tracker.
func (fetcher *ArchlinuxFetcher) FetchUpdate() (resp updater.FetcherResponse, err error) {
	log.Info("fetching Archlinux vulneratibilities")

	r, err := http.Get(archLinuxCVEURL)
	if err != nil {
		log.Errorf("could not download Archlinux CVE wiki content: %s", err)
		return resp, cerrors.ErrCouldNotDownload
	}
	defer r.Body.Close()
	flag, err := database.GetFlagValue(archlinuxUpdaterFlag)
	if err != nil {
		return resp, err
	}

	resp, err = parseArchlinuxWikiCVE(r.Body, flag)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

func parseArchlinuxWikiCVE(reader io.Reader, flag string) (resp updater.FetcherResponse, err error) {
	scanner := bufio.NewScanner(reader)
	re := regexp.MustCompile(tokensRegexp)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "{{CVE|CVE") {
			if !strings.Contains(line, "CVE-2014-????") {
				cve := buildArchlinuxCVE(re.ReplaceAllString(line, ""))
				vulnerability := &database.Vulnerability{
					ID:          cve.CVEID,
					Link:        cve.ASAID.URL,
					Description: cve.ASAID.Name,
				}
				resp.Vulnerabilities = append(
					resp.Vulnerabilities, vulnerability)
			}
		}
	}

	return resp, nil
}

func buildArchlinuxCVE(line string) ArchCVE {
	data := strings.Split(strings.TrimSpace(line), "||")
	sa := SecurityAdvisory{}
	if len(data) == 8 {
		dataSecurity := strings.Split(strings.TrimSpace(data[7]), " ")
		if len(dataSecurity) == 2 {
			sa.Name = dataSecurity[1]
			sa.URL = dataSecurity[0]
		} else {
			sa.Name = data[7]
		}
	}
	title := data[0]
	dataTitle := strings.Split(strings.TrimSpace(data[0]), "|")
	if len(dataTitle) >= 1 {
		title = dataTitle[2]
	}
	return ArchCVE{
		CVEID:           title,
		Package:         strings.Replace(strings.TrimSpace(data[1]), "|", "", -1),
		DisclosureDate:  strings.TrimSpace(data[2]),
		AffectedVersion: strings.TrimSpace(data[3]),
		FixedInVersion:  strings.TrimSpace(data[4]),
		ResponseTime:    strings.TrimSpace(data[5]),
		Status:          strings.TrimSpace(data[6]),
		ASAID:           sa,
	}
}
