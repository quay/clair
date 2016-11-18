// Copyright 2016 clair authors
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

// Package alpine implements a vulnerability Fetcher using the alpine-secdb
// git repository.
package alpine

import (
	"errors"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/coreos/pkg/capnslog"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/updater"
	"github.com/coreos/clair/utils"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/coreos/clair/utils/types"
)

const (
	secdbGitURL  = "http://git.alpinelinux.org/cgit/alpine-secdb"
	updaterFlag  = "alpine-secdbUpdater"
	nvdURLPrefix = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="
)

var (
	// ErrFilesystem is returned when a fetcher fails to interact with the local filesystem.
	ErrFilesystem = errors.New("updater/fetchers: something went wrong when interacting with the fs")

	// ErrGitFailure is returned when a fetcher fails to interact with git.
	ErrGitFailure = errors.New("updater/fetchers: something went wrong when interacting with git")

	log = capnslog.NewPackageLogger("github.com/coreos/clair", "updater/fetchers/alpine")
)

func init() {
	updater.RegisterFetcher("alpine", &fetcher{})
}

type fetcher struct {
	repositoryLocalPath string
}

func (f *fetcher) FetchUpdate(db database.Datastore) (resp updater.FetcherResponse, err error) {
	log.Info("fetching Alpine vulnerabilities")

	// Pull the master branch.
	var commit string
	commit, err = f.pullRepository()
	if err != nil {
		return
	}

	// Ask the database for the latest commit we successfully applied.
	var dbCommit string
	dbCommit, err = db.GetKeyValue(updaterFlag)
	if err != nil {
		return
	}

	// Set the updaterFlag to equal the commit processed.
	resp.FlagName = updaterFlag
	resp.FlagValue = commit

	// Short-circuit if there have been no updates.
	if commit == dbCommit {
		log.Debug("no alpine update")
		return
	}

	// Append any changed vulnerabilities to the response.
	for _, namespace := range []string{"v3.3", "v3.4"} {
		var file io.ReadCloser
		file, err = os.Open(f.repositoryLocalPath + "/" + namespace + "/main.yaml")
		if err != nil {
			return
		}

		var vulns []database.Vulnerability
		vulns, err = parseYAML(file)
		if err != nil {
			return
		}
		resp.Vulnerabilities = append(resp.Vulnerabilities, vulns...)
		file.Close()
	}

	return
}

func (f *fetcher) pullRepository() (commit string, err error) {
	if _, pathExists := os.Stat(f.repositoryLocalPath); f.repositoryLocalPath == "" || os.IsNotExist(pathExists) {
		if f.repositoryLocalPath, err = ioutil.TempDir(os.TempDir(), "alpine-secdb"); err != nil {
			return "", ErrFilesystem
		}

		if out, err := utils.Exec(f.repositoryLocalPath, "git", "pull"); err != nil {
			f.Clean()
			log.Errorf("could not pull alpine-secdb repository: %s. output: %s", err, out)
			return "", cerrors.ErrCouldNotDownload
		}
	}

	out, err := utils.Exec(f.repositoryLocalPath, "git", "rev-parse", "HEAD")
	if err != nil {
		return "", ErrGitFailure
	}

	commit = strings.TrimSpace(string(out))
	return
}

func (f *fetcher) Clean() {
	if f.repositoryLocalPath != "" {
		os.RemoveAll(f.repositoryLocalPath)
	}
}

type secdbFile struct {
	Distro   string `yaml:"distroversion"`
	Packages []struct {
		Pkg struct {
			Name    string   `yaml:"name"`
			Version string   `yaml:"ver"`
			Fixes   []string `yaml:"fixes"`
		} `yaml:"pkg"`
	} `yaml:"packages"`
}

func parseYAML(r io.Reader) (vulns []database.Vulnerability, err error) {
	var rBytes []byte
	rBytes, err = ioutil.ReadAll(r)
	if err != nil {
		return
	}

	var file secdbFile
	err = yaml.Unmarshal(rBytes, &file)
	if err != nil {
		return
	}
	for _, pack := range file.Packages {
		pkg := pack.Pkg
		for _, fix := range pkg.Fixes {
			version, err := types.NewVersion(pkg.Version)
			if err != nil {
				log.Warningf("could not parse package version '%s': %s. skipping", pkg.Version, err.Error())
				continue
			}

			var vuln database.Vulnerability
			vuln.Name = fix
			vuln.Link = nvdURLPrefix + fix
			vuln.FixedIn = []database.FeatureVersion{
				{
					Feature: database.Feature{
						Namespace: database.Namespace{Name: "alpine:" + file.Distro},
						Name:      pkg.Name,
					},
					Version: version,
				},
			}

			vulns = append(vulns, vuln)
		}
	}

	return
}
