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

// Package alpinerelease implements a featurens.Detector for Alpine Linux based
// container image layers.
package alpinerelease

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurens"
	"github.com/coreos/clair/ext/versionfmt/dpkg"
	"github.com/coreos/clair/pkg/tarutil"
)

const (
	osName            = "alpine"
	alpineReleasePath = "etc/alpine-release"
)

var versionRegexp = regexp.MustCompile(`^(\d)+\.(\d)+\.(\d)+$`)

func init() {
	featurens.RegisterDetector("alpine-release", &detector{})
}

type detector struct{}

func (d detector) Detect(files tarutil.FilesMap) (*database.Namespace, error) {
	file, exists := files[alpineReleasePath]
	if exists {
		scanner := bufio.NewScanner(bytes.NewBuffer(file))
		for scanner.Scan() {
			line := scanner.Text()
			match := versionRegexp.FindStringSubmatch(line)
			if len(match) > 0 {
				versionNumbers := strings.Split(match[0], ".")
				return &database.Namespace{
					Name:          osName + ":" + "v" + versionNumbers[0] + "." + versionNumbers[1],
					VersionFormat: dpkg.ParserName,
				}, nil
			}
		}
	}

	return nil, nil
}

func (d detector) RequiredFilenames() []string {
	return []string{alpineReleasePath}
}
