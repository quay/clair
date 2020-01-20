// Copyright 2020 clair authors
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
	"bytes"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/asottile/dockerfile"
	"github.com/buildkite/interpolate"
	"github.com/quay/clair/v3/database"
	"github.com/quay/clair/v3/ext/versionfmt/rpm"
	"github.com/quay/clair/v3/pkg/tarutil"
)

type CpeNamespaceFetcher interface {
	GetCPEs(nvr, arch string) ([]string, error)
}

// getPotentialNamespace - potential namespaces is based on CPEs strings.
// Based on NVRa of the image we find corresponding image in Red Hat's image
// metadata API and extract CPEs from there
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
	cpes, err := l.namespaceFetcher.GetCPEs(nvr, arch)
	if err != nil {
		log.WithError(err).WithField("nvr", nvr).Warning("Unable to get image CPEs")
		return
	}
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

// extractBuildNVR - extract build NVR (name-version-release) from Dockerfile
// stored in filesystem/
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
		// no interpolation has been done
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
