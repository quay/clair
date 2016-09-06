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

package opensuse

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/coreos/clair/updater"
	"github.com/coreos/clair/utils/oval"
	"github.com/coreos/pkg/capnslog"
)

var log = capnslog.NewPackageLogger("github.com/coreos/clair", "updater/fetchers/sle")

func init() {
	opensuseInfo := &OpenSUSEInfo{}

	updater.RegisterFetcher(opensuseInfo.DistName(),
		&oval.OvalFetcher{OsInfo: opensuseInfo})
}

// OpenSUSEInfo implements oval.OsInfo interface
// See oval.OsInfo for more info on what each method is
type OpenSUSEInfo struct {
}

func (f *OpenSUSEInfo) SecToken() string {
	return "CVE"
}

func (f *OpenSUSEInfo) IgnoredCriterions() []string {
	return []string{}
}

func (f *OpenSUSEInfo) OvalURI() string {
	return "http://ftp.suse.com/pub/projects/security/oval/"
}

func (f *OpenSUSEInfo) DistName() string {
	return "opensuse"
}

func (f *OpenSUSEInfo) Namespace() string {
	return f.DistName()
}

func (f *OpenSUSEInfo) ParseOsVersion(comment string) string {
	return f.ParseOsVersionR(comment, f.CritSystem())
}

func (f *OpenSUSEInfo) ParseOsVersionR(comment string, exp *regexp.Regexp) string {
	systemMatch := exp.FindStringSubmatch(comment)
	if len(systemMatch) < 2 {
		return ""
	}
	osVersion := systemMatch[1]
	if len(systemMatch) == 4 && systemMatch[3] != "" {
		sp := systemMatch[3]
		osVersion = fmt.Sprintf("%s.%s", osVersion, sp)
	}

	return osVersion
}

func (f *OpenSUSEInfo) ParsePackageNameVersion(comment string) (string, string) {
	packageMatch := f.CritPackage().FindStringSubmatch(comment)

	if len(packageMatch) != 3 {
		return "", ""
	}
	name := packageMatch[1]
	version := packageMatch[2]
	return name, version
}

func (f *OpenSUSEInfo) ParseFilenameDist(line string) string {
	return f.ParseFilenameDistR(line, f.DistRegexp(), f.DistMinVersion())
}

func (f *OpenSUSEInfo) ParseFilenameDistR(line string, exp *regexp.Regexp, minVersion float64) string {
	r := exp.FindStringSubmatch(line)
	if len(r) != 2 {
		return ""
	}
	if r[0] == "" || r[1] == "" {
		return ""
	}
	distVersion, _ := strconv.ParseFloat(r[1], 32)
	if distVersion < minVersion {
		return ""
	}
	return f.DistFile(r[0])
}

// These are not in the interface

func (f *OpenSUSEInfo) DistFile(item string) string {
	return f.OvalURI() + item
}

func (f *OpenSUSEInfo) CritSystem() *regexp.Regexp {
	return regexp.MustCompile(`openSUSE [^0-9]*(\d+\.\d+)[^0-9]* is installed`)
}

func (f *OpenSUSEInfo) CritPackage() *regexp.Regexp {
	return regexp.MustCompile(`(.*)-(.*\-[\d\.]+) is installed`)
}

func (f *OpenSUSEInfo) DistRegexp() *regexp.Regexp {
	return regexp.MustCompile(`opensuse.[^0-9]*(\d+\.\d+).xml`)
}

func (f *OpenSUSEInfo) DistMinVersion() float64 {
	return 13.1
}
