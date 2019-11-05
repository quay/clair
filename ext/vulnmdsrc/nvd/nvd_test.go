// Copyright 2018 clair authors
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

package nvd

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNVDParser(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename))

	dataFilePath := filepath.Join(path, "/testdata/nvd_test.json")
	testData, err := os.Open(dataFilePath)
	if err != nil {
		t.Fatalf("Error opening %q: %v", dataFilePath, err)
	}
	defer testData.Close()

	a := &appender{}
	a.metadata = make(map[string]NVDMetadata)

	err = a.parseDataFeed(testData)
	if err != nil {
		t.Fatalf("Error parsing %q: %v", dataFilePath, err)
	}

	var gotMetadata, wantMetadata NVDMetadata

	// Items without CVSSv2 aren't returned.
	assert.Len(t, a.metadata, 2)
	gotMetadata, ok := a.metadata["CVE-2002-0001"]
	assert.False(t, ok)

	// Item with only CVSSv2.
	gotMetadata, ok = a.metadata["CVE-2012-0001"]
	assert.True(t, ok)
	wantMetadata = NVDMetadata{
		CVSSv2: NVDmetadataCVSSv2{
			Vectors: "AV:N/AC:L/Au:S/C:P/I:N/A:N",
			Score:   4.0,
		},
	}
	assert.Equal(t, wantMetadata, gotMetadata)

	// Item with both CVSSv2 and CVSSv3 has CVSSv2 information returned.
	gotMetadata, ok = a.metadata["CVE-2018-0001"]
	assert.True(t, ok)
	wantMetadata = NVDMetadata{
		CVSSv2: NVDmetadataCVSSv2{
			Vectors: "AV:N/AC:L/Au:N/C:P/I:P/A:P",
			Score:   7.5,
		},
		CVSSv3: NVDmetadataCVSSv3{
			Vectors:             "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Score:               9.8,
			ExploitabilityScore: 3.9,
			ImpactScore:         5.9,
		},
	}
	assert.Equal(t, wantMetadata, gotMetadata)
}

func TestNVDParserErrors(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename))

	dataFilePath := filepath.Join(path, "/testdata/nvd_test_incorrect_format.json")
	testData, err := os.Open(dataFilePath)
	if err != nil {
		t.Fatalf("Error opening %q: %v", dataFilePath, err)
	}
	defer testData.Close()

	a := &appender{}
	a.metadata = make(map[string]NVDMetadata)

	err = a.parseDataFeed(testData)
	if err == nil {
		t.Fatalf("Expected error parsing NVD data file: %q", dataFilePath)
	}
}
