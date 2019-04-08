// Copyright 2019 clair authors
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

package testutil

import (
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/pkg/pagination"
	"github.com/stretchr/testify/assert"
)

func AssertVulnerabilityNotificationWithVulnerableEqual(t *testing.T, key pagination.Key, expected, actual *database.VulnerabilityNotificationWithVulnerable) bool {
	if expected == actual {
		return true
	}

	if expected == nil || actual == nil {
		return assert.Equal(t, expected, actual)
	}

	return assert.Equal(t, expected.NotificationHook, actual.NotificationHook) &&
		AssertPagedVulnerableAncestriesEqual(t, key, expected.Old, actual.Old) &&
		AssertPagedVulnerableAncestriesEqual(t, key, expected.New, actual.New)
}

func AssertPagedVulnerableAncestriesEqual(t *testing.T, key pagination.Key, expected, actual *database.PagedVulnerableAncestries) bool {
	if expected == actual {
		return true
	}

	if expected == nil || actual == nil {
		return assert.Equal(t, expected, actual)
	}

	return database.AssertVulnerabilityEqual(t, &expected.Vulnerability, &actual.Vulnerability) &&
		assert.Equal(t, expected.Limit, actual.Limit) &&
		assert.Equal(t, mustUnmarshalToken(key, expected.Current), mustUnmarshalToken(key, actual.Current)) &&
		assert.Equal(t, mustUnmarshalToken(key, expected.Next), mustUnmarshalToken(key, actual.Next)) &&
		assert.Equal(t, expected.End, actual.End) &&
		database.AssertIntStringMapEqual(t, expected.Affected, actual.Affected)
}

func AssertVulnerabilityWithAffectedEqual(t *testing.T, expected database.VulnerabilityWithAffected, actual database.VulnerabilityWithAffected) bool {
	return assert.Equal(t, expected.Vulnerability, actual.Vulnerability) && AssertAffectedFeaturesEqual(t, expected.Affected, actual.Affected)
}

func AssertAffectedFeaturesEqual(t *testing.T, expected []database.AffectedFeature, actual []database.AffectedFeature) bool {
	if assert.Len(t, actual, len(expected)) {
		has := map[database.AffectedFeature]bool{}
		for _, i := range expected {
			has[i] = false
		}
		for _, i := range actual {
			if visited, ok := has[i]; !ok {
				return false
			} else if visited {
				return false
			}
			has[i] = true
		}
		return true
	}
	return false
}

func AssertNamespacedFeatureEqual(t *testing.T, expected []database.NamespacedFeature, actual []database.NamespacedFeature) bool {
	if assert.Len(t, actual, len(expected)) {
		has := map[database.NamespacedFeature]bool{}
		for _, nf := range expected {
			has[nf] = false
		}

		for _, nf := range actual {
			has[nf] = true
		}

		for nf, visited := range has {
			if !assert.True(t, visited, nf.Namespace.Name+":"+nf.Name+" is expected") {
				return false
			}
		}
		return true
	}
	return false
}
