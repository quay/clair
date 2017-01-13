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

// Package redhatrelease implements a featurens.Detector for container image
// layers containing an redhat-release-like files.
//
// This detector is typically useful for detecting CentOS and Red-Hat like
// systems.
package redhatrelease

import (
	"regexp"
	"strings"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurens"
	"github.com/coreos/clair/ext/versionfmt/rpm"
	"github.com/coreos/clair/pkg/tarutil"
)

var (
	oracleReleaseRegexp = regexp.MustCompile(`(?P<os>[^\s]*) (Linux Server release) (?P<version>[\d]+)`)
	centosReleaseRegexp = regexp.MustCompile(`(?P<os>[^\s]*) (Linux release|release) (?P<version>[\d]+)`)
	redhatReleaseRegexp = regexp.MustCompile(`(?P<os>Red Hat Enterprise Linux) (Client release|Server release|Workstation release) (?P<version>[\d]+)`)
)

type detector struct{}

func init() {
	featurens.RegisterDetector("redhat-release", &detector{})
}

func (d detector) Detect(files tarutil.FilesMap) (*database.Namespace, error) {
	for _, filePath := range d.RequiredFilenames() {
		f, hasFile := files[filePath]
		if !hasFile {
			continue
		}

		var r []string

		// Attempt to match Oracle Linux.
		r = oracleReleaseRegexp.FindStringSubmatch(string(f))
		if len(r) == 4 {
			return &database.Namespace{
				Name:          strings.ToLower(r[1]) + ":" + r[3],
				VersionFormat: rpm.ParserName,
			}, nil
		}

		// Attempt to match RHEL.
		r = redhatReleaseRegexp.FindStringSubmatch(string(f))
		if len(r) == 4 {
			// TODO(vbatts): this is a hack until https://github.com/coreos/clair/pull/193
			return &database.Namespace{
				Name:          "centos" + ":" + r[3],
				VersionFormat: rpm.ParserName,
			}, nil
		}

		// Atempt to match CentOS.
		r = centosReleaseRegexp.FindStringSubmatch(string(f))
		if len(r) == 4 {
			return &database.Namespace{
				Name:          strings.ToLower(r[1]) + ":" + r[3],
				VersionFormat: rpm.ParserName,
			}, nil
		}
	}

	return nil, nil
}

func (d detector) RequiredFilenames() []string {
	return []string{"etc/oracle-release", "etc/centos-release", "etc/redhat-release", "etc/system-release"}
}
