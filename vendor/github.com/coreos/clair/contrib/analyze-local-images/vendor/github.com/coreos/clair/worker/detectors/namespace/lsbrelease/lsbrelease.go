// Copyright 2015 clair authors
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

package lsbrelease

import (
	"bufio"
	"regexp"
	"strings"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/worker/detectors"
)

var (
	lsbReleaseOSRegexp      = regexp.MustCompile(`^DISTRIB_ID=(.*)`)
	lsbReleaseVersionRegexp = regexp.MustCompile(`^DISTRIB_RELEASE=(.*)`)
)

// AptSourcesNamespaceDetector implements NamespaceDetector and detects the Namespace from the
// /etc/lsb-release file.
//
// This detector is necessary for Ubuntu Precise.
type LsbReleaseNamespaceDetector struct{}

func init() {
	detectors.RegisterNamespaceDetector("lsb-release", &LsbReleaseNamespaceDetector{})
}

func (detector *LsbReleaseNamespaceDetector) Detect(data map[string][]byte) *database.Namespace {
	f, hasFile := data["etc/lsb-release"]
	if !hasFile {
		return nil
	}

	var OS, version string

	scanner := bufio.NewScanner(strings.NewReader(string(f)))
	for scanner.Scan() {
		line := scanner.Text()

		r := lsbReleaseOSRegexp.FindStringSubmatch(line)
		if len(r) == 2 {
			OS = strings.Replace(strings.ToLower(r[1]), "\"", "", -1)
		}

		r = lsbReleaseVersionRegexp.FindStringSubmatch(line)
		if len(r) == 2 {
			version = strings.Replace(strings.ToLower(r[1]), "\"", "", -1)

			// We care about the .04 for Ubuntu but not for Debian / CentOS
			if OS == "centos" || OS == "debian" {
				i := strings.Index(version, ".")
				if i >= 0 {
					version = version[:i]
				}
			}
		}
	}

	if OS != "" && version != "" {
		return &database.Namespace{Name: OS + ":" + version}
	}
	return nil
}

// GetRequiredFiles returns the list of files that are required for Detect()
func (detector *LsbReleaseNamespaceDetector) GetRequiredFiles() []string {
	return []string{"etc/lsb-release"}
}
