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

package clair

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/coreos/clair/database"
)

func TestDoVulnerabilitiesNamespacing(t *testing.T) {
	fv1 := database.FeatureVersion{
		Feature: database.Feature{
			Namespace: database.Namespace{Name: "Namespace1"},
			Name:      "Feature1",
		},
		Version: "0.1",
	}

	fv2 := database.FeatureVersion{
		Feature: database.Feature{
			Namespace: database.Namespace{Name: "Namespace2"},
			Name:      "Feature1",
		},
		Version: "0.2",
	}

	fv3 := database.FeatureVersion{
		Feature: database.Feature{
			Namespace: database.Namespace{Name: "Namespace2"},
			Name:      "Feature2",
		},
		Version: "0.3",
	}

	vulnerability := database.Vulnerability{
		Name:    "DoVulnerabilityNamespacing",
		FixedIn: []database.FeatureVersion{fv1, fv2, fv3},
	}

	vulnerabilities := doVulnerabilitiesNamespacing([]database.Vulnerability{vulnerability})
	for _, vulnerability := range vulnerabilities {
		switch vulnerability.Namespace.Name {
		case fv1.Feature.Namespace.Name:
			assert.Len(t, vulnerability.FixedIn, 1)
			assert.Contains(t, vulnerability.FixedIn, fv1)
		case fv2.Feature.Namespace.Name:
			assert.Len(t, vulnerability.FixedIn, 2)
			assert.Contains(t, vulnerability.FixedIn, fv2)
			assert.Contains(t, vulnerability.FixedIn, fv3)
		default:
			t.Errorf("Should not have a Vulnerability with '%s' as its Namespace.", vulnerability.Namespace.Name)
			fmt.Printf("%#v\n", vulnerability)
		}
	}
}
