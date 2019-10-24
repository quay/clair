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

// Package redhatrpm implements a featurefmt.Lister for Red Hat's rpm packages.
package redhatrpm

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/asottile/dockerfile"
	"github.com/deckarep/golang-set"
	log "github.com/sirupsen/logrus"

	"github.com/buildkite/interpolate"
	"github.com/quay/clair/v3/database"
	"github.com/quay/clair/v3/ext/featurefmt"
	"github.com/quay/clair/v3/ext/versionfmt"
	"github.com/quay/clair/v3/ext/versionfmt/rpm"
	"github.com/quay/clair/v3/pkg/commonerr"
	"github.com/quay/clair/v3/pkg/tarutil"
)

var ignoredPackages = []string{
	"gpg-pubkey", // Ignore gpg-pubkey packages which are fake packages used to store GPG keys - they are not versionned properly.
}

var NamespaceHolderPackage = database.Feature{
	Name: "namespaceholder", Version: "0", VersionFormat: "rpm", Type: "rh-special",
}

var Name = "redhat-rpm"

type CpeNamespaceFetcher interface {
	GetCPEs(nvr, arch string) []string
}

type lister struct {
	namespaceFetcher CpeNamespaceFetcher
}

func init() {
	featurefmt.RegisterLister(Name, "1.0", &lister{&LBCpeNamespaceFetcher{}})
}

func (l lister) RequiredFilenames() []string {
	return []string{"var/lib/rpm/Packages", "root/buildinfo"}
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
	namespaces := l.getPotentialNamespace(files)
	packages := mapset.NewSet()
	f, hasFile := files["var/lib/rpm/Packages"]
	if hasFile {
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
		out, err := exec.Command(
			"rpm",
			"--dbpath", tmpDir,
			"-qa",
			"--qf", "%{NAME} %{EPOCH}:%{VERSION}-%{RELEASE} %{SOURCERPM}\n",
		).CombinedOutput()
		if err != nil {
			log.WithError(err).WithField("output", string(out)).Error("failed to query RPM")
			// Do not bubble up because we probably won't be able to fix it,
			// the database must be corrupted
			return []database.LayerFeature{}, nil
		}

		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		for scanner.Scan() {
			rpmPackage := parseRPMOutput(scanner.Text())
			if rpmPackage != nil {
				packages.Add(*rpmPackage)
			}

		}
	}

	layerFeatures := database.ConvertFeatureSetToLayerFeatures(packages)

	var layerFeaturesNamespace []database.LayerFeature
	// Add fake package which holds information about layer CPE namespace
	for _, namespace := range namespaces {
		fakeFeature := database.LayerFeature{
			Feature:            NamespaceHolderPackage,
			PotentialNamespace: namespace}
		layerFeaturesNamespace = append(layerFeaturesNamespace, fakeFeature)
	}
	for _, feature := range layerFeatures {
		if len(namespaces) == 0 {
			// no potential namespace have been found
			layerFeaturesNamespace = append(layerFeaturesNamespace, feature)
		} else {
			// make a feature for every potential namespace
			for _, namespace := range namespaces {
				feature.PotentialNamespace = namespace
				layerFeaturesNamespace = append(layerFeaturesNamespace, feature)
			}
		}
	}
	return layerFeaturesNamespace, nil
}

func parseRPMOutput(raw string) (rpmPackage *database.Feature) {
	line := strings.Split(raw, " ")
	if len(line) != 3 {
		// We may see warnings on some RPM versions:
		// "warning: Generating 12 missing index(es), please wait..."
		return
	}

	if isIgnored(line[0]) {
		return
	}

	name, version := line[0], strings.Replace(line[1], "(none):", "", -1)
	if err := versionfmt.Valid(rpm.ParserName, version); err != nil {
		log.WithError(err).WithFields(log.Fields{"name": name, "version": version}).Warning("skipped unparseable package")
		return
	}

	rpmPackage = &database.Feature{Name: name, Version: version, VersionFormat: rpm.ParserName, Type: database.BinaryPackage}
	return
}

// getPotentialNamespace - potential namespaces is based on CPEs strings
// based on NVRa of the image we find corresponding image in Lightblue
// and extract CPEs from there
// CPEs are used to identify Red Hat's products
func (l lister) getPotentialNamespace(files tarutil.FilesMap) (namespaces []database.Namespace) {
	dockerfilePath := findDockerfile(files)
	var nvr, arch string
	if dockerfilePath != "" {
		nvr, arch = extractBuildNVR(dockerfilePath, files)
	}
	if nvr == "" || arch == "" {
		return
	}
	log.WithField("nvr", nvr).Debug("Found layer identification")
	cpes := l.namespaceFetcher.GetCPEs(nvr, arch)
	log.WithField("cpes", cpes).Debug("Found CPEs for given layer")
	for _, cpe := range cpes {
		namespace := database.Namespace{
			Name:          cpe,
			VersionFormat: rpm.ParserName,
		}
		namespaces = append(namespaces, namespace)
	}
	return
}

// findDockerfile in filemap - RedHat stores Dockerfiles into /root/buildinfo/
func findDockerfile(files tarutil.FilesMap) string {
	for filePath := range files {
		if !strings.HasPrefix(filePath, "root/buildinfo/Dockerfile-") {
			continue
		}
		return filePath
	}
	return ""
}

// extractBuildNVR - extract build NVR from Dockerfile stored in filesystem
// The redhat.com.component LABEL is extracted from dockerfile and it is used as name
// Version and release is extracted from Dockerfile name
// Arch is extracted from 'architecture' LABEL
func extractBuildNVR(dockerfilePath string, files tarutil.FilesMap) (nvr, arch string) {
	dfData := files[dockerfilePath]
	r := bytes.NewReader(dfData)
	df, _ := dockerfile.ParseReader(r)
	var name string
	envVariable := interpolate.NewMapEnv(buildVarMap(df))
	for _, cmd := range df {
		if cmd.Cmd == "label" {
			for i, value := range cmd.Value {
				switch strings.Trim(value, "\"") {
				case "com.redhat.component":
					name = strings.Trim(cmd.Value[i+1], "\"")
					interpolatedName, err := interpolateName(name, envVariable)
					if err != nil {
						log.Debug("Can't interpolate name from Dockerfile: " + name)
					} else {
						name = interpolatedName
					}
				case "architecture":
					arch = strings.Trim(cmd.Value[i+1], "\"")
				}

			}
		}
	}
	_, fileName := filepath.Split(dockerfilePath)
	version, release := parseVersionRelease(fileName)
	nvr = name + "-" + version + "-" + release
	return
}

func buildVarMap(commands []dockerfile.Command) map[string]string {
	output := make(map[string]string)
	for _, cmd := range commands {
		if cmd.Cmd == "env" || cmd.Cmd == "arg" {
			for i := 0; i < len(cmd.Value)-1; i = i + 2 {
				key := strings.Trim(cmd.Value[i], "\"")
				output[key] = strings.Trim(cmd.Value[i+1], "\"")
			}
		}
	}
	return output
}

func interpolateName(name string, envVariable interpolate.Env) (interpolatedName string, err error) {
	interpolatedName, err = interpolate.Interpolate(envVariable, name)
	if err != nil {
		return interpolatedName, err
	}
	if name == interpolatedName {
		// no interpolation have been done
		return interpolatedName, nil
	}
	// there is still some variable in name
	return interpolateName(interpolatedName, envVariable)
}

// parseVersionRelease - parse release and version from NVR
func parseVersionRelease(nvr string) (version, release string) {
	releaseIndex := strings.LastIndex(nvr, "-")
	release = nvr[releaseIndex+1:]

	versionIndex := strings.LastIndex(nvr[:releaseIndex], "-")
	version = nvr[versionIndex+1 : releaseIndex]
	return
}
