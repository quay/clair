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

// Package modulerpm implements a featurefmt.Lister for modular rpm packages.
package modulerpm

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/quay/clair/v3/database"
	"github.com/quay/clair/v3/ext/featurefmt"
	"github.com/quay/clair/v3/ext/versionfmt"
	"github.com/quay/clair/v3/ext/versionfmt/modulerpm"
	"github.com/quay/clair/v3/pkg/commonerr"
	"github.com/quay/clair/v3/pkg/tarutil"
)

var ignoredPackages = []string{
	"gpg-pubkey", // Ignore gpg-pubkey packages which are fake packages used to store GPG keys - they are not versionned properly.
}

type lister struct{}

func init() {
	featurefmt.RegisterLister("module-rpm", "1.0", &lister{})
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
	tmpDir, err := ioutil.TempDir(os.TempDir(), "modulerpm")
	defer os.RemoveAll(tmpDir)
	if err != nil {
		log.WithError(err).Error("could not create temporary folder for module RPM detection")
		return []database.LayerFeature{}, commonerr.ErrFilesystem
	}

	err = ioutil.WriteFile(tmpDir+"/Packages", f, 0700)
	if err != nil {
		log.WithError(err).Error("could not create temporary file for module RPM detection")
		return []database.LayerFeature{}, commonerr.ErrFilesystem
	}

	// Extract binary package names because RHSA refers to binary package names.
	out, err := exec.Command(
		"rpm", "--dbpath", tmpDir, "-qa", "--qf", "%{NAME} %{EPOCH}:%{VERSION}-%{RELEASE} %{RPMTAG_MODULARITYLABEL}\n").Output()
	if err != nil {
		log.WithError(err).WithField("output", string(out)).Error("failed to query module RPM")
		// Do not bubble up because we probably won't be able to fix it,
		// the database must be corrupted
		return []database.LayerFeature{}, nil
	}

	packages := []database.LayerFeature{}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		rpmPackage := parseRPMOutput(scanner.Text())
		if rpmPackage == nil {
			continue
		}
		packages = append(packages, *rpmPackage)

	}

	return packages, nil
}

func parseRPMOutput(raw string) (rpmPackage *database.LayerFeature) {
	line := strings.Split(raw, " ")
	if len(line) != 3 {
		// We may see warnings on some RPM versions:
		// "warning: Generating 12 missing index(es), please wait..."
		return
	}

	if isIgnored(line[0]) {
		return
	}
	if !isModuleRpm(line) {
		return
	}

	name, version := line[0], strings.Replace(line[1], "(none):", "", -1)
	if err := versionfmt.Valid(modulerpm.ParserName, version); err != nil {
		log.WithError(err).WithFields(log.Fields{"name": name, "version": version}).Warning("skipped unparseable package")
		return
	}
	// module format: name:stream:version:context
	moduleSplit := strings.Split(line[2], ":")
	if len(moduleSplit) < 2 {
		return
	}

	rpmPackage = &database.LayerFeature{
		Feature:            database.Feature{Name: name, Version: version, VersionFormat: modulerpm.ParserName, Type: database.BinaryPackage},
		PotentialNamespace: database.Namespace{Name: fmt.Sprintf("%s:%s", moduleSplit[0], moduleSplit[1]), VersionFormat: modulerpm.ParserName},
	}
	return
}

func isModuleRpm(rpmOut []string) bool {
	return rpmOut[2] != "(none)"
}
