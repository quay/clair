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

package sle

import (
	"regexp"

	"github.com/coreos/clair/updater"
	"github.com/coreos/clair/updater/fetchers/opensuse"
	"github.com/coreos/clair/utils/oval"
	"github.com/coreos/pkg/capnslog"
)

var log = capnslog.NewPackageLogger("github.com/coreos/clair", "updater/fetchers/sle")
var opensuseInfo = &opensuse.OpenSUSEInfo{}

func init() {
	sleInfo := &SLEInfo{}

	updater.RegisterFetcher(sleInfo.DistName(),
		&oval.OvalFetcher{OsInfo: sleInfo})
}

// SLEInfo implements oval.OsInfo interface
// See oval.OsInfo for more info on what each method is
// SLE and openSUSE shares most of the code, there are just subtle diffs on
// the name and versions of the distribution
type SLEInfo struct {
}

func (f *SLEInfo) SecToken() string {
	return opensuseInfo.SecToken()
}

func (f *SLEInfo) IgnoredCriterions() []string {
	return opensuseInfo.IgnoredCriterions()
}

func (f *SLEInfo) OvalURI() string {
	return opensuseInfo.OvalURI()
}

// This differs from openSUSE
func (f *SLEInfo) DistName() string {
	return "sle"
}

func (f *SLEInfo) Namespace() string {
	return f.DistName()
}

func (f *SLEInfo) ParseOsVersion(comment string) string {
	return opensuseInfo.ParseOsVersionR(comment, f.CritSystem())
}

func (f *SLEInfo) ParsePackageNameVersion(comment string) (string, string) {
	return opensuseInfo.ParsePackageNameVersion(comment)
}

func (f *SLEInfo) ParseFilenameDist(line string) string {
	return opensuseInfo.ParseFilenameDistR(line, f.DistRegexp(), f.DistMinVersion())
}

// These are diffs with openSUSE

func (f *SLEInfo) CritSystem() *regexp.Regexp {
	return regexp.MustCompile(`SUSE Linux Enterprise Server [^0-9]*(\d+)\s*(SP(\d+)|) is installed`)
}

func (f *SLEInfo) DistRegexp() *regexp.Regexp {
	return regexp.MustCompile(`suse.linux.enterprise.(\d+).xml`)
}

func (f *SLEInfo) DistMinVersion() float64 {
	return 11.4
}
