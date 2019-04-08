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

// Package rpm implements a featurefmt.Lister for rpm packages.
package rpm

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/deckarep/golang-set"
	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/rpm"
	"github.com/coreos/clair/pkg/commonerr"
	"github.com/coreos/clair/pkg/strutil"
	"github.com/coreos/clair/pkg/tarutil"
)

var ignoredPackages = []string{
	"gpg-pubkey", // Ignore gpg-pubkey packages which are fake packages used to store GPG keys - they are not versionned properly.
}

type lister struct{}

func init() {
	featurefmt.RegisterLister("rpm", "1.0", &lister{})
}

func (l lister) RequiredFilenames() []string {
	return []string{"^var/lib/rpm/Packages"}
}

func isIgnored(packageName string) bool {
	for _, pkg := range ignoredPackages {
		if pkg == packageName {
			return true
		}
	}

	return false
}

func (l lister) ListFeatures(files tarutil.FilesMap) ([]database.LayerFeature, error) {
	f, hasFile := files["var/lib/rpm/Packages"]
	if !hasFile {
		return []database.LayerFeature{}, nil
	}

	// Write the required "Packages" file to disk
	tmpDir, err := ioutil.TempDir(os.TempDir(), "rpm")
	defer os.RemoveAll(tmpDir)
	if err != nil {
		log.WithError(err).Error("could not create temporary folder for RPM detection")
		return []database.LayerFeature{}, commonerr.ErrFilesystem
	}

	err = ioutil.WriteFile(tmpDir+"/Packages", f, 0700)
	if err != nil {
		log.WithError(err).Error("could not create temporary file for RPM detection")
		return []database.LayerFeature{}, commonerr.ErrFilesystem
	}

	// Extract binary package names because RHSA refers to binary package names.
	out, err := exec.Command("rpm", "--dbpath", tmpDir, "-qa", "--qf", "%{NAME} %{EPOCH}:%{VERSION}-%{RELEASE} %{SOURCERPM}\n").CombinedOutput()
	if err != nil {
		log.WithError(err).WithField("output", string(out)).Error("failed to query RPM")
		// Do not bubble up because we probably won't be able to fix it,
		// the database must be corrupted
		return []database.LayerFeature{}, nil
	}

	packages := mapset.NewSet()
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		rpmPackage, srpmPackage := parseRPMOutput(scanner.Text())
		if rpmPackage != nil {
			packages.Add(*rpmPackage)
		}

		if srpmPackage != nil {
			packages.Add(*srpmPackage)
		}
	}

	return database.ConvertFeatureSetToLayerFeatures(packages), nil
}

func parseRPMOutput(raw string) (rpmPackage *database.Feature, srpmPackage *database.Feature) {
	line := strings.Split(raw, " ")
	if len(line) != 3 {
		// We may see warnings on some RPM versions:
		// "warning: Generating 12 missing index(es), please wait..."
		return
	}

	if isIgnored(line[0]) {
		return
	}

	name, version, srpm := line[0], strings.Replace(line[1], "(none):", "", -1), line[2]
	if err := versionfmt.Valid(rpm.ParserName, version); err != nil {
		log.WithError(err).WithFields(log.Fields{"name": name, "version": version}).Warning("skipped unparseable package")
		return
	}

	rpmPackage = &database.Feature{name, version, rpm.ParserName, database.BinaryPackage}
	srpmName, srpmVersion, srpmRelease, _, err := parseSourceRPM(srpm)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{"name": name, "sourcerpm": srpm}).Warning("skipped unparseable package")
		return
	}

	srpmVersion = srpmVersion + "-" + srpmRelease
	if err = versionfmt.Valid(rpm.ParserName, srpmVersion); err != nil {
		return
	}

	srpmPackage = &database.Feature{srpmName, srpmVersion, rpm.ParserName, database.SourcePackage}
	return
}

type rpmParserState string

const (
	terminate         rpmParserState = "terminate"
	parseRPM          rpmParserState = "RPM Token"
	parseArchitecture rpmParserState = "Architecture Token"
	parseRelease      rpmParserState = "Release Token"
	parseVersion      rpmParserState = "Version Token"
)

// parseSourceRPM parses the source rpm package representation string
// http://ftp.rpm.org/max-rpm/ch-rpm-file-format.html
func parseSourceRPM(sourceRPM string) (name string, version string, release string, architecture string, err error) {
	state := parseRPM
	previousCheckPoint := len(sourceRPM)
	for i := len(sourceRPM) - 1; i >= 0; i-- {
		switch state {
		case parseRPM:
			if string(sourceRPM[i]) == "." {
				state = parseArchitecture
				packageType := strutil.Substring(sourceRPM, i+1, len(sourceRPM))
				previousCheckPoint = i
				if packageType != "rpm" {
					err = fmt.Errorf("unexpected package type, expect: 'rpm', got: '%s'", packageType)
					return
				}
			}
		case parseArchitecture:
			if string(sourceRPM[i]) == "." {
				state = parseRelease
				architecture = strutil.Substring(sourceRPM, i+1, previousCheckPoint)
				previousCheckPoint = i
				if architecture != "src" && architecture != "nosrc" {
					err = fmt.Errorf("unexpected package architecture, expect: 'src' or 'nosrc', got: '%s'", architecture)
					return
				}
			}
		case parseRelease:
			if string(sourceRPM[i]) == "-" {
				state = parseVersion
				release = strutil.Substring(sourceRPM, i+1, previousCheckPoint)
				previousCheckPoint = i
				if release == "" {
					err = fmt.Errorf("unexpected package release, expect: not empty")
					return
				}
			}
		case parseVersion:
			if string(sourceRPM[i]) == "-" {
				// terminate state
				state = terminate
				version = strutil.Substring(sourceRPM, i+1, previousCheckPoint)
				previousCheckPoint = i
				if version == "" {
					err = fmt.Errorf("unexpected package version, expect: not empty")
					return
				}
				break
			}
		}
	}

	if state != terminate {
		err = fmt.Errorf("unexpected termination while parsing '%s'", state)
		return
	}

	name = strutil.Substring(sourceRPM, 0, previousCheckPoint)
	if name == "" {
		err = fmt.Errorf("unexpected package name, expect: not empty")
		return
	}

	return
}
