// Copyright 2016 clair authors
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

package alpinerelease

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/worker/detectors"
)

const (
	osName            = "alpine"
	alpineReleasePath = "etc/alpine-release"
)

var versionRegexp = regexp.MustCompile(`^(\d)+\.(\d)+\.(\d)+$`)

func init() {
	detectors.RegisterNamespaceDetector("alpine-release", &detector{})
}

// detector implements NamespaceDetector by reading the current version of
// Alpine Linux from /etc/alpine-release.
type detector struct{}

func (d *detector) Detect(data map[string][]byte) *database.Namespace {
	file, exists := data[alpineReleasePath]
	if exists {
		scanner := bufio.NewScanner(bytes.NewBuffer(file))
		for scanner.Scan() {
			line := scanner.Text()
			match := versionRegexp.FindStringSubmatch(line)
			if len(match) > 0 {
				versionNumbers := strings.Split(match[0], ".")
				return &database.Namespace{
					Name:          osName + ":" + "v" + versionNumbers[0] + "." + versionNumbers[1],
					VersionFormat: "dpkg",
				}
			}
		}
	}

	return nil
}

func (d *detector) GetRequiredFiles() []string {
	return []string{alpineReleasePath}
}
