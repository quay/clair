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

// Package amzn implements a vulnerability source updater using
// ALAS (Amazon Linux Security Advisories).
package amzn

import (
	"bufio"
	"compress/gzip"
	"encoding/xml"
	"io"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/rpm"
	"github.com/coreos/clair/ext/vulnsrc"
	"github.com/coreos/clair/pkg/commonerr"
	"github.com/coreos/clair/pkg/httputil"
)

const (
	amazonLinux1Name          = "Amazon Linux 2018.03"
	amazonLinux1Namespace     = "amzn:2018.03"
	amazonLinux1UpdaterFlag   = "amazonLinux1Updater"
	amazonLinux1MirrorListURI = "http://repo.us-west-2.amazonaws.com/2018.03/updates/x86_64/mirror.list"
	amazonLinux2Name          = "Amazon Linux 2"
	amazonLinux2Namespace     = "amzn:2"
	amazonLinux2UpdaterFlag   = "amazonLinux2Updater"
	amazonLinux2MirrorListURI = "https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list"
)

type updater struct {
	Name          string
	Namespace     string
	UpdaterFlag   string
	MirrorListURI string
}

func init() {
	// Register updater for Amazon Linux 2018.03.
	amazonLinux1Updater := updater{
		Name:          amazonLinux1Name,
		Namespace:     amazonLinux1Namespace,
		UpdaterFlag:   amazonLinux1UpdaterFlag,
		MirrorListURI: amazonLinux1MirrorListURI,
	}
	vulnsrc.RegisterUpdater("amzn", &amazonLinux1Updater)

	// Register updater for Amazon Linux 2.
	amazonLinux2Updater := updater{
		Name:          amazonLinux2Name,
		Namespace:     amazonLinux2Namespace,
		UpdaterFlag:   amazonLinux2UpdaterFlag,
		MirrorListURI: amazonLinux2MirrorListURI,
	}
	vulnsrc.RegisterUpdater("amzn2", &amazonLinux2Updater)
}

func (u *updater) Update(datastore database.Datastore) (response vulnsrc.UpdateResponse, err error) {
	log.WithField("package", u.Name).Info("Start fetching vulnerabilities")

	// Get the flag value (the timestamp of the latest ALAS of the previous update).
	flagValue, found, err := database.FindKeyValueAndRollback(datastore, u.UpdaterFlag)
	if err != nil {
		return response, err
	}

	if !found {
		flagValue = ""
	}

	var timestamp string

	// Get the ALASs from updateinfo.xml.gz from the repos.
	updateInfo, err := u.getUpdateInfo()
	if err != nil {
		return response, err
	}

	// Get the ALASs which were issued/updated since the previous update.
	var alasList []ALAS
	for _, alas := range updateInfo.ALASList {
		if compareTimestamp(alas.Updated.Date, flagValue) > 0 {
			alasList = append(alasList, alas)

			if compareTimestamp(alas.Updated.Date, timestamp) > 0 {
				timestamp = alas.Updated.Date
			}
		}
	}

	// Get the vulnerabilities.
	response.Vulnerabilities, err = u.alasListToVulnerabilities(alasList)
	if err != nil {
		return response, err
	}

	// Set the flag value.
	if timestamp != "" {
		response.FlagName = u.UpdaterFlag
		response.FlagValue = timestamp
	} else {
		log.WithField("package", u.Name).Debug("no update")
	}

	return response, err
}

func (u *updater) Clean() {

}

func (u *updater) getUpdateInfo() (updateInfo UpdateInfo, err error) {
	// Get the URI of updateinfo.xml.gz.
	updateInfoURI, err := u.getUpdateInfoURI()
	if err != nil {
		return updateInfo, err
	}

	// Download updateinfo.xml.gz.
	updateInfoResponse, err := httputil.GetWithUserAgent(updateInfoURI)
	if err != nil {
		log.WithError(err).Error("could not download updateinfo.xml.gz")
		return updateInfo, commonerr.ErrCouldNotDownload
	}
	defer updateInfoResponse.Body.Close()

	if !httputil.Status2xx(updateInfoResponse) {
		log.WithField("StatusCode", updateInfoResponse.StatusCode).Error("could not download updateinfo.xml.gz")
		return updateInfo, commonerr.ErrCouldNotDownload
	}

	// Decompress updateinfo.xml.gz.
	updateInfoXml, err := gzip.NewReader(updateInfoResponse.Body)
	if err != nil {
		log.WithError(err).Error("could not decompress updateinfo.xml.gz")
		return updateInfo, commonerr.ErrCouldNotDownload
	}
	defer updateInfoXml.Close()

	// Decode updateinfo.xml.
	updateInfo, err = decodeUpdateInfo(updateInfoXml)
	if err != nil {
		log.WithError(err).Error("could not decode updateinfo.xml")
		return updateInfo, err
	}

	return
}

func (u *updater) getUpdateInfoURI() (updateInfoURI string, err error) {
	// Download mirror.list
	mirrorListResponse, err := httputil.GetWithUserAgent(u.MirrorListURI)
	if err != nil {
		log.WithError(err).Error("could not download mirror list")
		return updateInfoURI, commonerr.ErrCouldNotDownload
	}
	defer mirrorListResponse.Body.Close()

	if !httputil.Status2xx(mirrorListResponse) {
		log.WithField("StatusCode", mirrorListResponse.StatusCode).Error("could not download mirror list")
		return updateInfoURI, commonerr.ErrCouldNotDownload
	}

	// Parse the URI of the first mirror.
	scanner := bufio.NewScanner(mirrorListResponse.Body)
	success := scanner.Scan()
	if success != true {
		log.WithError(err).Error("could not parse mirror list")
	}
	mirrorURI := scanner.Text()

	// Download repomd.xml.
	repoMdURI := mirrorURI + "/repodata/repomd.xml"
	repoMdResponse, err := httputil.GetWithUserAgent(repoMdURI)
	if err != nil {
		log.WithError(err).Error("could not download repomd.xml")
		return updateInfoURI, commonerr.ErrCouldNotDownload
	}
	defer repoMdResponse.Body.Close()

	if !httputil.Status2xx(repoMdResponse) {
		log.WithField("StatusCode", repoMdResponse.StatusCode).Error("could not download repomd.xml")
		return updateInfoURI, commonerr.ErrCouldNotDownload
	}

	// Decode repomd.xml.
	var repoMd RepoMd
	err = xml.NewDecoder(repoMdResponse.Body).Decode(&repoMd)
	if err != nil {
		log.WithError(err).Error("could not decode repomd.xml")
		return updateInfoURI, commonerr.ErrCouldNotDownload
	}

	// Parse the URI of updateinfo.xml.gz.
	for _, repo := range repoMd.RepoList {
		if repo.Type == "updateinfo" {
			updateInfoURI = mirrorURI + "/" + repo.Location.Href
			break
		}
	}
	if updateInfoURI == "" {
		log.Error("could not find updateinfo in repomd.xml")
		return updateInfoURI, commonerr.ErrCouldNotDownload
	}

	return
}

func decodeUpdateInfo(updateInfoReader io.Reader) (updateInfo UpdateInfo, err error) {
	err = xml.NewDecoder(updateInfoReader).Decode(&updateInfo)
	if err != nil {
		return updateInfo, err
	}

	return
}

func (u *updater) alasListToVulnerabilities(alasList []ALAS) (vulnerabilities []database.VulnerabilityWithAffected, err error) {
	for _, alas := range alasList {
		featureVersions := u.alasToFeatureVersions(alas)
		if len(featureVersions) > 0 {
			vulnerability := database.VulnerabilityWithAffected{
				Vulnerability: database.Vulnerability{
					Name:        u.alasToName(alas),
					Link:        u.alasToLink(alas),
					Severity:    u.alasToSeverity(alas),
					Description: u.alasToDescription(alas),
				},
				Affected: featureVersions,
			}
			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}

	return
}

func (u *updater) alasToName(alas ALAS) string {
	return alas.Id
}

func (u *updater) alasToLink(alas ALAS) string {
	if u.Name == amazonLinux1Name {
		return "https://alas.aws.amazon.com/" + alas.Id + ".html"
	}

	// "ALAS2-2018-1097" becomes "https://alas.aws.amazon.com/AL2/ALAS-2018-1097.html".
	re := regexp.MustCompile(`^ALAS2-(.+)$`)
	return "https://alas.aws.amazon.com/AL2/ALAS-" + re.FindStringSubmatch(alas.Id)[1] + ".html"
}

func (u *updater) alasToSeverity(alas ALAS) database.Severity {
	switch alas.Severity {
	case "low":
		return database.LowSeverity
	case "medium":
		return database.MediumSeverity
	case "important":
		return database.HighSeverity
	case "critical":
		return database.CriticalSeverity
	default:
		log.WithField("severity", alas.Severity).Warning("could not determine vulnerability severity")
		return database.UnknownSeverity
	}
}

func (u *updater) alasToDescription(alas ALAS) string {
	re := regexp.MustCompile(`\s+`)
	return re.ReplaceAllString(strings.TrimSpace(alas.Description), " ")
}

func (u *updater) alasToFeatureVersions(alas ALAS) (featureVersions []database.AffectedFeature) {
	for _, p := range alas.Packages {
		var version string
		if p.Epoch == "0" {
			version = p.Version + "-" + p.Release
		} else {
			version = p.Epoch + ":" + p.Version + "-" + p.Release
		}
		err := versionfmt.Valid(rpm.ParserName, version)
		if err != nil {
			log.WithError(err).WithField("version", version).Warning("could not parse package version. skipping")
			continue
		}

		var featureVersion database.AffectedFeature
		featureVersion.Namespace.Name = u.Namespace
		featureVersion.Namespace.VersionFormat = rpm.ParserName
		featureVersion.FeatureName = p.Name
		featureVersion.AffectedVersion = version
		if version != versionfmt.MaxVersion {
			featureVersion.FixedInVersion = version
		}
		featureVersion.AffectedType = database.AffectBinaryPackage

		featureVersions = append(featureVersions, featureVersion)
	}

	return
}

func compareTimestamp(date0 string, date1 string) int {
	// format: YYYY-MM-DD hh:mm
	if date0 < date1 {
		return -1
	} else if date0 > date1 {
		return 1
	} else {
		return 0
	}
}
