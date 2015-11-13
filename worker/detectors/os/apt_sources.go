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

// Package os defines OSDetector for several sources.
package os

import (
	"bufio"
	"strings"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/worker/detectors"
)

// AptSourcesOSDetector implements OSDetector and detects the OS from the
// /etc/apt/sources.list file.
type AptSourcesOSDetector struct{}

func init() {
	detectors.RegisterOSDetector("apt-sources", &AptSourcesOSDetector{})
}

// Detect tries to detect OS/Version using /etc/apt/sources.list
// Necessary to determine precise Debian version when it is an unstable version for instance
func (detector *AptSourcesOSDetector) Detect(data map[string][]byte) (OS, version string) {
	f, hasFile := data["etc/apt/sources.list"]
	if !hasFile {
		return
	}

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

	return
}

// GetRequiredFiles returns the list of files that are required for Detect()
func (detector *AptSourcesOSDetector) GetRequiredFiles() []string {
	return []string{"etc/apt/sources.list"}
}
