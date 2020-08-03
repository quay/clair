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
	"gopkg.in/yaml.v2"
	"io"
	"os"
	"path/filepath"

	"github.com/quay/clair/v3/database"
	"github.com/quay/clair/v3/ext/versionfmt"
	"github.com/quay/clair/v3/ext/versionfmt/dpkg"
	"github.com/quay/clair/v3/ext/vulnsrc"
	"github.com/quay/clair/v3/pkg/fsutil"
	log "github.com/sirupsen/logrus"
	//"github.com/quay/clair/v3/pkg/gitutil"

	"crypto/sha256"
	"encoding/hex"
	"github.com/PuerkitoBio/goquery"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	// This Alpine vulnerability database affects origin packages, which has
	// `origin` field of itself.
	// secdbGitURL  = "https://github.com/alpinelinux/alpine-secdb" // No longer valid
	baseURL = "https://secdb.alpinelinux.org/" // Web source for alpine vuln data
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
	currentDir string
	hash_slice [][32] byte
}

func (u *updater) processFile(filename string) {
	nameParts := strings.Split(filename, ".")
	if nameParts[1] == "json" {
		return
	}

	response, err := http.Get(baseURL + u.currentDir + filename)
	if err != nil {
		//log.WithError(err).WithField("package", "Alpine").Error("Failed to get vuln file")
		return
	}
	defer response.Body.Close()

	file, err := os.Create(filepath.Join(filepath.Join(u.repositoryLocalPath, u.currentDir), filename))
	if err != nil {
		log.WithField("package", "Alpine").Fatal(err)
		return
	}
	defer file.Close()

	// find hash of file contents as part of checking for changes
	file_hasher := sha256.New()
	fileContents, err := ioutil.ReadAll(response.Body)
	file_hasher.Write([] byte(fileContents[:]))

	// Must be a better way to achieve this...
	var file_hash [32]byte
	copy(file_hash[:], file_hasher.Sum(nil))
	u.hash_slice = append(u.hash_slice, file_hash)

	file.WriteString(string(fileContents[:]))
	return
}

func (u *updater) processFiles(index int, element *goquery.Selection) {
	href, exists := element.Attr("href")
	if exists {
		if href != "../" {
			u.processFile(href)
		}
	}
}

func (u *updater) processVersionDir(versionDir string) {
	response, err := http.Get(baseURL + versionDir)
	if err != nil {
		log.WithError(err).WithField("package", "Alpine").Error("Failed to get version")
	}
	defer response.Body.Close()

	document, err := goquery.NewDocumentFromReader(response.Body)
	if err != nil {
		log.Fatal("Error loading HTTP response body. ", err)
	}
	document.Find("a").Each(u.processFiles)
}

func (u *updater) processVersions(index int, element *goquery.Selection) {
	href, exists := element.Attr("href")
	if exists {
		if href != "../" {
			log.WithField("package", "Alpine").Debug(href)
			// create Version directory
			os.Mkdir(filepath.Join(u.repositoryLocalPath, href),0700)
			u.currentDir = href
			u.processVersionDir(href)
		}
	}
}

func sliceXOR (a, b [32]byte) (result [32]byte) {
	var tmpval [32]byte
	for i:=0; i<32; i++ {
		tmpval[i] = a[i] ^ b[i]
	}
	result = tmpval
	return
}

func (u *updater) getVulnFiles(repoPath, tempDirPrefix string) (commit string, err error) {
	log.WithField("package", "alpine").Debug("Getting vulnerability data...")

	// Set up temporary location for downlaods
	if repoPath == "" {
		u.repositoryLocalPath, err = ioutil.TempDir(os.TempDir(), tempDirPrefix)
		if err != nil {
			return
		}
	} else {
		u.repositoryLocalPath = repoPath
	}

	u.hash_slice = nil
	u.currentDir = ""

	// Get root directory of web server
	response, err := http.Get(baseURL)
	if err != nil {
		return
	}
	defer response.Body.Close()

	document, err := goquery.NewDocumentFromReader(response.Body)
	if err != nil {
		log.WithError(err).WithField("package", "Alpine").Fatal("Error loading HTTP response body. ")
		return
	}
	document.Find("a").Each(u.processVersions)

	// Find XOR of all file hash values to use as commit hash replacement. Used to detect for changes to source files
	var tmp_commit [32]byte
	for i:=0; i < len(u.hash_slice); i++ {
		tmp_commit = sliceXOR(tmp_commit, u.hash_slice[i])
	}
	commit = hex.EncodeToString(tmp_commit[:])

	return
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

	if commit, err = u.getVulnFiles(u.repositoryLocalPath, updaterFlag); err != nil {
		log.WithField("package", "alpine").Debug("no file updates, skip")
		return
	}

	// Set the updaterFlag to equal the commit processed.
	resp.Flags = make(map[string]string)
	resp.Flags[updaterFlag] = commit
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
