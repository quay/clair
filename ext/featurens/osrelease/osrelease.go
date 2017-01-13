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

// Package osrelease implements a featurens.Detector for container image
// layers containing an os-release file.
//
// This detector is typically useful for detecting Debian or Ubuntu.
package osrelease

import (
	"bufio"
	"regexp"
	"strings"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurens"
	"github.com/coreos/clair/ext/versionfmt/dpkg"
	"github.com/coreos/clair/ext/versionfmt/rpm"
	"github.com/coreos/clair/pkg/tarutil"
)

var (
	osReleaseOSRegexp      = regexp.MustCompile(`^ID=(.*)`)
	osReleaseVersionRegexp = regexp.MustCompile(`^VERSION_ID=(.*)`)

	// blacklistFilenames are files that should exclude this detector.
	blacklistFilenames = []string{
		"etc/oracle-release",
		"etc/redhat-release",
		"usr/lib/centos-release",
	}
)

type detector struct{}

func init() {
	featurens.RegisterDetector("os-release", &detector{})
}

func (d detector) Detect(files tarutil.FilesMap) (*database.Namespace, error) {
	var OS, version string

	for _, filePath := range blacklistFilenames {
		if _, hasFile := files[filePath]; hasFile {
			return nil, nil
		}
	}

	for _, filePath := range d.RequiredFilenames() {
		f, hasFile := files[filePath]
		if !hasFile {
			continue
		}

		scanner := bufio.NewScanner(strings.NewReader(string(f)))
		for scanner.Scan() {
			line := scanner.Text()

			r := osReleaseOSRegexp.FindStringSubmatch(line)
			if len(r) == 2 {
				OS = strings.Replace(strings.ToLower(r[1]), "\"", "", -1)
			}

			r = osReleaseVersionRegexp.FindStringSubmatch(line)
			if len(r) == 2 {
				version = strings.Replace(strings.ToLower(r[1]), "\"", "", -1)
			}
		}
	}

	// Determine the VersionFormat.
	var versionFormat string
	switch OS {
	case "debian", "ubuntu":
		versionFormat = dpkg.ParserName
	case "centos", "rhel", "fedora", "amzn", "ol", "oracle":
		versionFormat = rpm.ParserName
	default:
		return nil, nil
	}

	if OS != "" && version != "" {
		return &database.Namespace{
			Name:          OS + ":" + version,
			VersionFormat: versionFormat,
		}, nil
	}
	return nil, nil
}

func (d detector) RequiredFilenames() []string {
	return []string{"etc/os-release", "usr/lib/os-release"}
}
