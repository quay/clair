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

package redhatrelease

import (
	"regexp"
	"strings"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/worker/detectors"
)

var (
	redhatReleaseRegexp = regexp.MustCompile(`(?P<os>[^\s]*) (Linux release|release) (?P<version>[\d]+)`)

	redhatNSRegexps = []*regexp.Regexp{
		regexp.MustCompile(`^etc/centos-release$`),
		regexp.MustCompile(`^etc/redhat-release$`),
		regexp.MustCompile(`^etc/system-release$`),
	}
)

// RedhatReleaseNamespaceDetector implements NamespaceDetector and detects the OS from the
// /etc/centos-release, /etc/redhat-release and /etc/system-release files.
//
// Typically for CentOS and Red-Hat like systems
// eg. CentOS release 5.11 (Final)
// eg. CentOS release 6.6 (Final)
// eg. CentOS Linux release 7.1.1503 (Core)
type RedhatReleaseNamespaceDetector struct{}

func init() {
	detectors.RegisterNamespaceDetector("redhat-release", &RedhatReleaseNamespaceDetector{})
}

func (detector *RedhatReleaseNamespaceDetector) Detect(data map[string][]byte) *database.Namespace {
	for _, filePath := range []string{"etc/centos-release", "etc/redhat-release", "etc/system-release"} {
		f, hasFile := data[filePath]
		if !hasFile {
			continue
		}

		r := redhatReleaseRegexp.FindStringSubmatch(string(f))
		if len(r) == 4 {
			return &database.Namespace{Name: strings.ToLower(r[1]) + ":" + r[3]}
		}
	}

	return nil
}

// GetRequiredFiles returns the list of files that are required for Detect()
func (detector *RedhatReleaseNamespaceDetector) GetRequiredFiles() []*regexp.Regexp {
	return redhatNSRegexps
}
