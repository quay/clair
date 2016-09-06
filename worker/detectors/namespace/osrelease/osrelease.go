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

package osrelease

import (
	"bufio"
	"regexp"
	"strings"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/worker/detectors"
)

var (
	//log = capnslog.NewPackageLogger("github.com/coreos/clair", "worker/detectors/namespace/osrelease")

	osReleaseOSRegexp      = regexp.MustCompile(`^ID=(.*)`)
	osReleaseVersionRegexp = regexp.MustCompile(`^VERSION_ID=(.*)`)
)

// OsReleaseNamespaceDetector implements NamespaceDetector and detects the OS from the
// /etc/os-release and usr/lib/os-release files.
type OsReleaseNamespaceDetector struct{}

func init() {
	detectors.RegisterNamespaceDetector("os-release", &OsReleaseNamespaceDetector{})
}

// Detect tries to detect OS/Version using "/etc/os-release" and "/usr/lib/os-release"
// Typically for Debian / Ubuntu
// /etc/debian_version can't be used, it does not make any difference between testing and unstable, it returns stretch/sid
func (detector *OsReleaseNamespaceDetector) Detect(data map[string][]byte) *database.Namespace {
	var OS, version string

	for _, filePath := range detector.getExcludeFiles() {
		if _, hasFile := data[filePath]; hasFile {
			return nil
		}
	}

	for _, filePath := range detector.GetRequiredFiles() {
		f, hasFile := data[filePath]
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

	if OS != "" && version != "" {
		return &database.Namespace{Name: OS + ":" + version}
	}
	return nil
}

// GetRequiredFiles returns the list of files that are required for Detect()
func (detector *OsReleaseNamespaceDetector) GetRequiredFiles() []string {
	return []string{"etc/os-release", "usr/lib/os-release"}
}

// getExcludeFiles returns the list of files that are ought to exclude this detector from Detect()
func (detector *OsReleaseNamespaceDetector) getExcludeFiles() []string {
	return []string{"etc/redhat-release", "usr/lib/centos-release"}
}
