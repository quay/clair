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
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/PuerkitoBio/goquery"

	"github.com/quay/clair/v2/database"
	"github.com/quay/clair/v2/ext/versionfmt"
	"github.com/quay/clair/v2/ext/versionfmt/dpkg"
	"github.com/quay/clair/v2/ext/vulnsrc"
)

const (
	// secdbGitURL  = "https://github.com/alpinelinux/alpine-secdb"
	baseURL  = "https://secdb.alpinelinux.org/"
	updaterFlag  = "alpine-secdbUpdater"
	nvdURLPrefix = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="
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
	log.WithField("package", "Alpine").Info("Start fetching vulnerabilities")

	// Pull the master branch.
	var commit string

	if commit, err = u.getVulnFiles(u.repositoryLocalPath, updaterFlag); err != nil {
		log.WithField("package", "alpine").Debug("no file updates, skip")
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
		var vulns []database.Vulnerability
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

func parseVulnsFromNamespace(repositoryPath, namespace string) (vulns []database.Vulnerability, note string, err error) {
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

		var fileVulns []database.Vulnerability
		fileVulns, err = parseYAML(file)
		if err != nil {
			return
		}

		vulns = append(vulns, fileVulns...)
		file.Close()
	}

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

func parseYAML(r io.Reader) (vulns []database.Vulnerability, err error) {
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
				var vuln database.Vulnerability
				vuln.Severity = database.UnknownSeverity
				vuln.Name = vulnStr
				vuln.Link = nvdURLPrefix + vulnStr
				vuln.FixedIn = []database.FeatureVersion{
					{
						Feature: database.Feature{
							Namespace: database.Namespace{
								Name:          "alpine:" + file.Distro,
								VersionFormat: dpkg.ParserName,
							},
							Name: pkg.Name,
						},
						Version: version,
					},
				}
				vulns = append(vulns, vuln)
			}
		}
	}

	return
}
