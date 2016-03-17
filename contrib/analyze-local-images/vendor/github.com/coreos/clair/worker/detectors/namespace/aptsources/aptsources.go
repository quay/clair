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

package aptsources

import (
	"bufio"
	"strings"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/worker/detectors"
)

// AptSourcesNamespaceDetector implements NamespaceDetector and detects the Namespace from the
// /etc/apt/sources.list file.
//
// This detector is necessary to determine precise Debian version when it is
// an unstable version for instance.
type AptSourcesNamespaceDetector struct{}

func init() {
	detectors.RegisterNamespaceDetector("apt-sources", &AptSourcesNamespaceDetector{})
}

func (detector *AptSourcesNamespaceDetector) Detect(data map[string][]byte) *database.Namespace {
	f, hasFile := data["etc/apt/sources.list"]
	if !hasFile {
		return nil
	}

	var OS, version string

	scanner := bufio.NewScanner(strings.NewReader(string(f)))
	for scanner.Scan() {
		// Format: man sources.list | https://wiki.debian.org/SourcesList)
		// deb uri distribution component1 component2 component3
		// deb-src uri distribution component1 component2 component3
		line := strings.Split(scanner.Text(), " ")
		if len(line) > 3 {
			// Only consider main component
			isMainComponent := false
			for _, component := range line[3:] {
				if component == "main" {
					isMainComponent = true
					break
				}
			}
			if !isMainComponent {
				continue
			}

			var found bool
			version, found = database.DebianReleasesMapping[line[2]]
			if found {
				OS = "debian"
				break
			}
			version, found = database.UbuntuReleasesMapping[line[2]]
			if found {
				OS = "ubuntu"
				break
			}
		}
	}

	if OS != "" && version != "" {
		return &database.Namespace{Name: OS + ":" + version}
	}
	return nil
}

func (detector *AptSourcesNamespaceDetector) GetRequiredFiles() []string {
	return []string{"etc/apt/sources.list"}
}
