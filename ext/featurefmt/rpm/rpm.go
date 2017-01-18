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
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/coreos/pkg/capnslog"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/rpm"
	"github.com/coreos/clair/pkg/commonerr"
	"github.com/coreos/clair/pkg/tarutil"
)

var log = capnslog.NewPackageLogger("github.com/coreos/clair", "ext/featurefmt/rpm")

type lister struct{}

func init() {
	featurefmt.RegisterLister("rpm", &lister{})
}

func (l lister) ListFeatures(files tarutil.FilesMap) ([]database.FeatureVersion, error) {
	f, hasFile := files["var/lib/rpm/Packages"]
	if !hasFile {
		return []database.FeatureVersion{}, nil
	}

	// Create a map to store packages and ensure their uniqueness
	packagesMap := make(map[string]database.FeatureVersion)

	// Write the required "Packages" file to disk
	tmpDir, err := ioutil.TempDir(os.TempDir(), "rpm")
	defer os.RemoveAll(tmpDir)
	if err != nil {
		log.Errorf("could not create temporary folder for RPM detection: %s", err)
		return []database.FeatureVersion{}, commonerr.ErrFilesystem
	}

	err = ioutil.WriteFile(tmpDir+"/Packages", f, 0700)
	if err != nil {
		log.Errorf("could not create temporary file for RPM detection: %s", err)
		return []database.FeatureVersion{}, commonerr.ErrFilesystem
	}

	// Extract binary package names because RHSA refers to binary package names.
	out, err := exec.Command("rpm", "--dbpath", tmpDir, "-qa", "--qf", "%{NAME} %{EPOCH}:%{VERSION}-%{RELEASE}\n").CombinedOutput()
	if err != nil {
		log.Errorf("could not query RPM: %s. output: %s", err, string(out))
		// Do not bubble up because we probably won't be able to fix it,
		// the database must be corrupted
		return []database.FeatureVersion{}, nil
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.Split(scanner.Text(), " ")
		if len(line) != 2 {
			// We may see warnings on some RPM versions:
			// "warning: Generating 12 missing index(es), please wait..."
			continue
		}

		// Ignore gpg-pubkey packages which are fake packages used to store GPG keys - they are not versionned properly.
		if line[0] == "gpg-pubkey" {
			continue
		}

		// Parse version
		version := strings.Replace(line[1], "(none):", "", -1)
		err := versionfmt.Valid(rpm.ParserName, version)
		if err != nil {
			log.Warningf("could not parse package version '%s': %s. skipping", line[1], err.Error())
			continue
		}

		// Add package
		pkg := database.FeatureVersion{
			Feature: database.Feature{
				Name: line[0],
			},
			Version: version,
		}
		packagesMap[pkg.Feature.Name+"#"+pkg.Version] = pkg
	}

	// Convert the map to a slice
	packages := make([]database.FeatureVersion, 0, len(packagesMap))
	for _, pkg := range packagesMap {
		packages = append(packages, pkg)
	}

	return packages, nil
}

func (l lister) RequiredFilenames() []string {
	return []string{"var/lib/rpm/Packages"}
}
