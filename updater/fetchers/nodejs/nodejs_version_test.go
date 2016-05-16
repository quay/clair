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

package nodejs

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNodeVersion(t *testing.T) {
	invalid_version := "3.1.3 < 4.0.0 || >=  "
	versions := strings.Split(invalid_version, "||")
	for _, version := range versions {
		ovs := getOperVersions(version)
		assert.Len(t, ovs, 0)
	}

	valid_version := ">=3.1.3 < 4.0.0 || >=4.1.1"
	versions = strings.Split(valid_version, "||")
	for _, version := range versions {
		if strings.Contains(version, "4.1.1") {
			ovs := getOperVersions(version)
			assert.Len(t, ovs, 1)
			assert.Equal(t, ">=", ovs[0].Oper)
			assert.Equal(t, "4.1.1", ovs[0].Version)
		} else {
			ovs := getOperVersions(version)
			assert.Len(t, ovs, 2)

			for _, ov := range ovs {
				if ov.Oper == ">=" {
					assert.Equal(t, "3.1.3", ov.Version)
				} else if ov.Oper == "<" {
					assert.Equal(t, "4.0.0", ov.Version)
				}
			}
		}
	}
}
