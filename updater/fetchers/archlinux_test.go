// Copyright 2015, 2016 clair authors
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

package fetchers

import (
	//"fmt"
	"os"
	"path"
	"regexp"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestArchLinuxCVEBuilder(t *testing.T) {
	line := "| {{CVE|CVE-2014-9687}} [http://www.openwall.com/lists/oss-security/2015/02/10/10 templink] || {{pkg|ecryptfs-utils}} || 2015-02-10 || <= 104-1 || 106-1 || 37d || Fixed ({{bug|44157}}) || [https://lists.archlinux.org/pipermail/arch-security/2015-March/000255.html ASA-201503-14]"
	re := regexp.MustCompile(tokensRegexp)
	cve := buildArchLinuxCVE(re.ReplaceAllString(line, ""))
	expected := ArchLinuxCVE{
		CVEID:           "CVE-2014-9687 http://www.openwall.com/lists/oss-security/2015/02/10/10 templink",
		Package:         "ecryptfs-utils",
		DisclosureDate:  "2015-02-10",
		AffectedVersion: "<= 104-1",
		FixedInVersion:  "106-1",
		ResponseTime:    "37d",
		Status:          "Fixed (bug|44157)",
		ASAID: SecurityAdvisory{
			Name: "ASA-201503-14",
			URL:  "https://lists.archlinux.org/pipermail/arch-security/2015-March/000255.html",
		},
	}
	assert.Equal(t, expected, cve)
}

func TestArchlinuxParser(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	testFile, _ := os.Open(path.Join(path.Dir(filename), "/testdata/fetcher_archlinux.txt"))
	response, err := parseArchLinuxWikiCVE(testFile, "")
	defer testFile.Close()
	if err != nil {
		t.Fatalf("Error parsing Arch Linux CVE: %s %s",
			testFile.Name(), err.Error())
	}
	if response.Vulnerabilities == nil || len(response.Vulnerabilities) < 300 {
		t.Fatalf("Arch Linux vulnerabilities: %d", len(response.Vulnerabilities))
	}

	// if response.Packages != nil {
	// 	t.Fatalf("Arch vulnerabilities: %s", response.Vulnerabilities)
	// }
}
