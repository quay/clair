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

package os

import (
	"regexp"
	"strings"

	"github.com/coreos/clair/worker/detectors"
)

var redhatReleaseRegexp = regexp.MustCompile(`(?P<os>[^\s]*) (Linux release|release) (?P<version>[\d]+)`)

// RedhatReleaseOSDetector implements OSDetector and detects the OS from the
// /etc/centos-release, /etc/redhat-release and /etc/system-release files.
type RedhatReleaseOSDetector struct{}

func init() {
	detectors.RegisterOSDetector("redhat-release", &RedhatReleaseOSDetector{})
}

// Detect tries to detect OS/Version using "/etc/centos-release", "/etc/redhat-release" and "/etc/system-release"
// Typically for CentOS and Red-Hat like systems
// eg. CentOS release 5.11 (Final)
// eg. CentOS release 6.6 (Final)
// eg. CentOS Linux release 7.1.1503 (Core)
func (detector *RedhatReleaseOSDetector) Detect(data map[string][]byte) (OS, version string) {
	for _, filePath := range detector.GetRequiredFiles() {
		f, hasFile := data[filePath]
		if !hasFile {
			continue
		}

		r := redhatReleaseRegexp.FindStringSubmatch(string(f))
		if len(r) == 4 {
			OS = strings.ToLower(r[1])
			version = r[3]
		}
	}

	return
}

// GetRequiredFiles returns the list of files that are required for Detect()
func (detector *RedhatReleaseOSDetector) GetRequiredFiles() []string {
	return []string{"etc/centos-release", "etc/redhat-release", "etc/system-release"}
}
