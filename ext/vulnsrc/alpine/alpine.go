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

// Package alpine implements a vulnerability source updater using the
// alpine-secdb git repository.
package alpine

import (
	"io"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/dpkg"
	"github.com/coreos/clair/ext/vulnsrc"
	"github.com/coreos/clair/pkg/fsutil"
	"github.com/coreos/clair/pkg/gitutil"
)

const (
	// This Alpine vulnerability database affects origin packages, which has
	// `origin` field of itself.
	secdbGitURL  = "https://github.com/alpinelinux/alpine-secdb"
	updaterFlag  = "alpine-secdbUpdater"
	nvdURLPrefix = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="
	// affected type indicates if the affected feature hint is for binary or
	// source package.
	affectedType = database.BinaryPackage
)

func init() {
	vulnsrc.RegisterUpdater("alpine", &updater{})
}

type updater struct {
	repositoryLocalPath string
}

func (u *updater) Update(db database.Datastore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", "Alpine").Info("start fetching vulnerabilities")
	// Pull the master branch.
	var (
		commit         string
		existingCommit string
		foundCommit    bool
		namespaces     []string
		vulns          []database.VulnerabilityWithAffected
	)

	if u.repositoryLocalPath, commit, err = gitutil.CloneOrPull(secdbGitURL, u.repositoryLocalPath, updaterFlag); err != nil {
		return
	}

	// Set the updaterFlag to equal the commit processed.
	resp.FlagName = updaterFlag
	resp.FlagValue = commit
	if existingCommit, foundCommit, err = database.FindKeyValueAndRollback(db, updaterFlag); err != nil {
		return
	}

	// Short-circuit if there have been no updates.
	if foundCommit && commit == existingCommit {
		log.WithField("package", "alpine").Debug("no update, skip")
		return
	}

	// Get the list of namespaces from the repository.
	if namespaces, err = fsutil.Readdir(u.repositoryLocalPath, fsutil.DirectoriesOnly); err != nil {
		return
	}

	// Append any changed vulnerabilities to the response.
	for _, namespace := range namespaces {
		if vulns, err = parseVulnsFromNamespace(u.repositoryLocalPath, namespace); err != nil {
			return
		}

		resp.Vulnerabilities = append(resp.Vulnerabilities, vulns...)
	}

	return
}

func (u *updater) Clean() {
	if u.repositoryLocalPath != "" {
		os.RemoveAll(u.repositoryLocalPath)
	}
}

func parseVulnsFromNamespace(repositoryPath, namespace string) (vulns []database.VulnerabilityWithAffected, err error) {
	nsDir := filepath.Join(repositoryPath, namespace)
	var dbFilenames []string
	if dbFilenames, err = fsutil.Readdir(nsDir, fsutil.FilesOnly); err != nil {
		return
	}

	for _, filename := range dbFilenames {
		var db *secDB
		if db, err = newSecDB(filepath.Join(nsDir, filename)); err != nil {
			return
		}

		vulns = append(vulns, db.Vulnerabilities()...)
	}

	return
}

type secDB struct {
	Distro   string `yaml:"distroversion"`
	Packages []struct {
		Pkg struct {
			Name  string              `yaml:"name"`
			Fixes map[string][]string `yaml:"secfixes"`
		} `yaml:"pkg"`
	} `yaml:"packages"`
}

func newSecDB(filePath string) (file *secDB, err error) {
	var f io.ReadCloser
	f, err = os.Open(filePath)
	if err != nil {
		return
	}

	defer f.Close()
	file = &secDB{}
	err = yaml.NewDecoder(f).Decode(file)
	return
}

func (file *secDB) Vulnerabilities() (vulns []database.VulnerabilityWithAffected) {
	if file == nil {
		return
	}

	namespace := database.Namespace{Name: "alpine:" + file.Distro, VersionFormat: dpkg.ParserName}
	for _, pkg := range file.Packages {
		for version, cveNames := range pkg.Pkg.Fixes {
			if err := versionfmt.Valid(dpkg.ParserName, version); err != nil {
				log.WithError(err).WithFields(log.Fields{
					"version":      version,
					"package name": pkg.Pkg.Name,
				}).Warning("could not parse package version, skipping")
				continue
			}

			for _, cve := range cveNames {
				vuln := database.VulnerabilityWithAffected{
					Vulnerability: database.Vulnerability{
						Name:      cve,
						Link:      nvdURLPrefix + cve,
						Severity:  database.UnknownSeverity,
						Namespace: namespace,
					},
				}

				var fixedInVersion string
				if version != versionfmt.MaxVersion {
					fixedInVersion = version
				}

				vuln.Affected = []database.AffectedFeature{
					{
						FeatureType:     affectedType,
						FeatureName:     pkg.Pkg.Name,
						AffectedVersion: version,
						FixedInVersion:  fixedInVersion,
						Namespace: database.Namespace{
							Name:          "alpine:" + file.Distro,
							VersionFormat: dpkg.ParserName,
						},
					},
				}
				vulns = append(vulns, vuln)
			}
		}
	}

	return
}
