// Copyright 2015 quay-sec authors
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

package os

import (
	"bufio"
	"regexp"
	"strings"

	"github.com/coreos/quay-sec/worker/detectors"
)

var (
	lsbReleaseOSRegexp      = regexp.MustCompile(`^DISTRIB_ID=(.*)`)
	lsbReleaseVersionRegexp = regexp.MustCompile(`^DISTRIB_RELEASE=(.*)`)
)

// AptSourcesOSDetector implements OSDetector and detects the OS from the
// /etc/lsb-release file.
type LsbReleaseOSDetector struct{}

func init() {
	detectors.RegisterOSDetector("lsb-release", &LsbReleaseOSDetector{})
}

// Detect tries to detect OS/Version using "/etc/lsb-release"
// Necessary for Ubuntu Precise for instance
func (detector *LsbReleaseOSDetector) Detect(data map[string][]byte) (OS, version string) {
	f, hasFile := data["etc/lsb-release"]
	if !hasFile {
		return
	}

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

	return
}

// GetRequiredFiles returns the list of files that are required for Detect()
func (detector *LsbReleaseOSDetector) GetRequiredFiles() []string {
	return []string{"etc/lsb-release"}
}
