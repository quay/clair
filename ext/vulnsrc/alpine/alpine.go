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

// Package alpine implements a vulnerability source updater using the
// alpine-secdb git repository.
package alpine

import (
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/dpkg"
	"github.com/coreos/clair/ext/vulnsrc"
	"github.com/coreos/clair/pkg/commonerr"
)

const (
	secdbGitURL  = "https://git.alpinelinux.org/cgit/alpine-secdb"
	updaterFlag  = "alpine-secdbUpdater"
	nvdURLPrefix = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="
)

func init() {
	vulnsrc.RegisterUpdater("alpine", &updater{})
}

type updater struct {
	repositoryLocalPath string
}

func (u *updater) Update(db database.Datastore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", "Alpine").Info("Start fetching vulnerabilities")

	// Pull the master branch.
	var commit string
	commit, err = u.pullRepository()
	if err != nil {
		return
	}

	// Open a database transaction.
	tx, err := db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()

	// Ask the database for the latest commit we successfully applied.
	var dbCommit string
	var ok bool
	dbCommit, ok, err = tx.FindKeyValue(updaterFlag)
	if err != nil {
		return
	}
	if !ok {
		dbCommit = ""
	}

	// Set the updaterFlag to equal the commit processed.
	resp.FlagName = updaterFlag
	resp.FlagValue = commit

	// Short-circuit if there have been no updates.
	if commit == dbCommit {
		log.WithField("package", "alpine").Debug("no update")
		return
	}

	// Get the list of namespaces from the repository.
	var namespaces []string
	namespaces, err = ls(u.repositoryLocalPath, directoriesOnly)
	if err != nil {
		return
	}

	// Append any changed vulnerabilities to the response.
	for _, namespace := range namespaces {
		var vulns []database.VulnerabilityWithAffected
		var note string
		vulns, note, err = parseVulnsFromNamespace(u.repositoryLocalPath, namespace)
		if err != nil {
			return
		}
		if note != "" {
			resp.Notes = append(resp.Notes, note)
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

type lsFilter int

const (
	filesOnly lsFilter = iota
	directoriesOnly
)

func ls(path string, filter lsFilter) ([]string, error) {
	dir, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer dir.Close()

	finfos, err := dir.Readdir(0)
	if err != nil {
		return nil, err
	}

	var files []string
	for _, info := range finfos {
		if filter == directoriesOnly && !info.IsDir() {
			continue
		}

		if filter == filesOnly && info.IsDir() {
			continue
		}

		if strings.HasPrefix(info.Name(), ".") {
			continue
		}

		files = append(files, info.Name())
	}

	return files, nil
}

func parseVulnsFromNamespace(repositoryPath, namespace string) (vulns []database.VulnerabilityWithAffected, note string, err error) {
	nsDir := filepath.Join(repositoryPath, namespace)
	var dbFilenames []string
	dbFilenames, err = ls(nsDir, filesOnly)
	if err != nil {
		return
	}

	for _, filename := range dbFilenames {
		var file io.ReadCloser
		file, err = os.Open(filepath.Join(nsDir, filename))
		if err != nil {
			return
		}

		var fileVulns []database.VulnerabilityWithAffected
		fileVulns, err = parseYAML(file)
		if err != nil {
			return
		}

		vulns = append(vulns, fileVulns...)
		file.Close()
	}

	return
}

func (u *updater) pullRepository() (commit string, err error) {
	// If the repository doesn't exist, clone it.
	if _, pathExists := os.Stat(u.repositoryLocalPath); u.repositoryLocalPath == "" || os.IsNotExist(pathExists) {
		if u.repositoryLocalPath, err = ioutil.TempDir(os.TempDir(), "alpine-secdb"); err != nil {
			return "", vulnsrc.ErrFilesystem
		}

		cmd := exec.Command("git", "clone", secdbGitURL, ".")
		cmd.Dir = u.repositoryLocalPath
		if out, err := cmd.CombinedOutput(); err != nil {
			u.Clean()
			log.WithError(err).WithField("output", string(out)).Error("could not clone alpine-secdb repository")
			return "", commonerr.ErrCouldNotDownload
		}
	} else {
		// The repository already exists and it needs to be refreshed via a pull.
		cmd := exec.Command("git", "pull")
		cmd.Dir = u.repositoryLocalPath
		if _, err := cmd.CombinedOutput(); err != nil {
			return "", vulnsrc.ErrGitFailure
		}
	}

	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = u.repositoryLocalPath
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", vulnsrc.ErrGitFailure
	}

	commit = strings.TrimSpace(string(out))
	return
}

type secDBFile struct {
	Distro   string `yaml:"distroversion"`
	Packages []struct {
		Pkg struct {
			Name  string              `yaml:"name"`
			Fixes map[string][]string `yaml:"secfixes"`
		} `yaml:"pkg"`
	} `yaml:"packages"`
}

func parseYAML(r io.Reader) (vulns []database.VulnerabilityWithAffected, err error) {
	var rBytes []byte
	rBytes, err = ioutil.ReadAll(r)
	if err != nil {
		return
	}

	var file secDBFile
	err = yaml.Unmarshal(rBytes, &file)
	if err != nil {
		return
	}

	for _, pack := range file.Packages {
		pkg := pack.Pkg
		for version, vulnStrs := range pkg.Fixes {
			err := versionfmt.Valid(dpkg.ParserName, version)
			if err != nil {
				log.WithError(err).WithField("version", version).Warning("could not parse package version. skipping")
				continue
			}

			for _, vulnStr := range vulnStrs {
				var vuln database.VulnerabilityWithAffected
				vuln.Severity = database.UnknownSeverity
				vuln.Name = vulnStr
				vuln.Link = nvdURLPrefix + vulnStr

				var fixedInVersion string
				if version != versionfmt.MaxVersion {
					fixedInVersion = version
				}
				vuln.Affected = []database.AffectedFeature{
					{
						FeatureName:     pkg.Name,
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
