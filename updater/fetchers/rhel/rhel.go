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

package rhel

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/coreos/clair/updater"
	"github.com/coreos/clair/utils/oval"
	"github.com/coreos/clair/utils/types"
	"github.com/coreos/pkg/capnslog"
)

const (
	// Before this RHSA, it deals only with RHEL <= 4.
	firstRHEL5RHSA      = 20070044
	firstConsideredRHEL = 5
)

var (
	rhsaRegexp = regexp.MustCompile(`com.redhat.rhsa-(\d+).xml`)
	log        = capnslog.NewPackageLogger("github.com/coreos/clair", "updater/fetchers/rhel")
)

func init() {
	rhelInfo := &RHELInfo{}
	updater.RegisterFetcher(rhelInfo.DistName(),
		&oval.OvalFetcher{OsInfo: rhelInfo})
}

// RHELInfo implements oval.OsInfo interface
// See oval.OsInfo for more info on what each method is
type RHELInfo struct {
}

func (f *RHELInfo) DistFile(item string) string {
	rhsaFilePrefix := "com.redhat.rhsa-"
	return f.OvalURI() + rhsaFilePrefix + item + ".xml"
}

func (f *RHELInfo) SecToken() string {
	return "RHSA"
}

func (f *RHELInfo) IgnoredCriterions() []string {
	return []string{
		" is signed with Red Hat ",
		" Client is installed",
		" Workstation is installed",
		" ComputeNode is installed",
	}
}

func (f *RHELInfo) OvalURI() string {
	return "https://www.redhat.com/security/data/oval/"
}

func (f *RHELInfo) DistName() string {
	return "RHEL"
}

func (f *RHELInfo) Namespace() string {
	return "centos"
}

func (f *RHELInfo) ParseOsVersion(comment string) string {
	if !strings.Contains(comment, " is installed") {
		return ""
	}
	const prefixLen = len("Red Hat Enterprise Linux ")
	osVersion := strings.TrimSpace(comment[prefixLen : prefixLen+strings.Index(comment[prefixLen:], " ")])
	if !f.ValidOsVersion(osVersion) {
		return ""
	}
	return osVersion
}

func (f *RHELInfo) ParsePackageNameVersion(comment string) (string, string) {
	if !strings.Contains(comment, " is earlier than ") {
		return "", ""
	}
	const prefixLen = len(" is earlier than ")
	name := strings.TrimSpace(comment[:strings.Index(comment, " is earlier than ")])
	version := comment[strings.Index(comment, " is earlier than ")+prefixLen:]
	return name, version
}

func (f *RHELInfo) ParseFilenameDist(line string) string {
	r := rhsaRegexp.FindStringSubmatch(line)
	if len(r) != 2 {
		return ""
	}
	rhsaNo, _ := strconv.Atoi(r[1])
	if rhsaNo <= firstRHEL5RHSA {
		return ""
	}
	return f.DistFile(r[1])
}

// Not in the interface

func (f *RHELInfo) ValidOsVersion(osVersion string) bool {
	version, err := strconv.Atoi(osVersion)
	if err != nil {
		return false
	}
	_, err = types.NewVersion(osVersion)
	if err != nil {
		return false
	}
	return version > firstConsideredRHEL
}
