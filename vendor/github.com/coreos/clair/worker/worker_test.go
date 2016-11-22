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

package worker

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/coreos/clair/database"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/coreos/clair/utils/types"

	// Register the required detectors.
	_ "github.com/coreos/clair/worker/detectors/data/docker"
	_ "github.com/coreos/clair/worker/detectors/feature/dpkg"
	_ "github.com/coreos/clair/worker/detectors/namespace/aptsources"
	_ "github.com/coreos/clair/worker/detectors/namespace/osrelease"
)

type mockDatastore struct {
	database.MockDatastore
	layers map[string]database.Layer
}

func newMockDatastore() *mockDatastore {
	return &mockDatastore{
		layers: make(map[string]database.Layer),
	}
}

func TestProcessWithDistUpgrade(t *testing.T) {
	_, f, _, _ := runtime.Caller(0)
	testDataPath := filepath.Join(filepath.Dir(f)) + "/testdata/DistUpgrade/"

	// Create a mock datastore.
	datastore := newMockDatastore()
	datastore.FctInsertLayer = func(layer database.Layer) error {
		datastore.layers[layer.Name] = layer
		return nil
	}
	datastore.FctFindLayer = func(name string, withFeatures, withVulnerabilities bool) (database.Layer, error) {
		if layer, exists := datastore.layers[name]; exists {
			return layer, nil
		}
		return database.Layer{}, cerrors.ErrNotFound
	}

	// Create the list of FeatureVersions that should not been upgraded from one layer to another.
	nonUpgradedFeatureVersions := []database.FeatureVersion{
		{Feature: database.Feature{Name: "libtext-wrapi18n-perl"}, Version: types.NewVersionUnsafe("0.06-7")},
		{Feature: database.Feature{Name: "libtext-charwidth-perl"}, Version: types.NewVersionUnsafe("0.04-7")},
		{Feature: database.Feature{Name: "libtext-iconv-perl"}, Version: types.NewVersionUnsafe("1.7-5")},
		{Feature: database.Feature{Name: "mawk"}, Version: types.NewVersionUnsafe("1.3.3-17")},
		{Feature: database.Feature{Name: "insserv"}, Version: types.NewVersionUnsafe("1.14.0-5")},
		{Feature: database.Feature{Name: "db"}, Version: types.NewVersionUnsafe("5.1.29-5")},
		{Feature: database.Feature{Name: "ustr"}, Version: types.NewVersionUnsafe("1.0.4-3")},
		{Feature: database.Feature{Name: "xz-utils"}, Version: types.NewVersionUnsafe("5.1.1alpha+20120614-2")},
	}

	// Process test layers.
	//
	// blank.tar: MAINTAINER Quentin MACHU <quentin.machu.fr>
	// wheezy.tar: FROM debian:wheezy
	// jessie.tar: RUN sed -i "s/precise/trusty/" /etc/apt/sources.list && apt-get update &&
	//             apt-get -y dist-upgrade
	assert.Nil(t, Process(datastore, "Docker", "blank", "", testDataPath+"blank.tar.gz", nil))
	assert.Nil(t, Process(datastore, "Docker", "wheezy", "blank", testDataPath+"wheezy.tar.gz", nil))
	assert.Nil(t, Process(datastore, "Docker", "jessie", "wheezy", testDataPath+"jessie.tar.gz", nil))

	// Ensure that the 'wheezy' layer has the expected namespace and features.
	wheezy, ok := datastore.layers["wheezy"]
	if assert.True(t, ok, "layer 'wheezy' not processed") {
		assert.Equal(t, "debian:7", wheezy.Namespace.Name)
		assert.Len(t, wheezy.Features, 52)

		for _, nufv := range nonUpgradedFeatureVersions {
			nufv.Feature.Namespace.Name = "debian:7"
			assert.Contains(t, wheezy.Features, nufv)
		}
	}

	// Ensure that the 'wheezy' layer has the expected namespace and non-upgraded features.
	jessie, ok := datastore.layers["jessie"]
	if assert.True(t, ok, "layer 'jessie' not processed") {
		assert.Equal(t, "debian:8", jessie.Namespace.Name)
		assert.Len(t, jessie.Features, 74)

		for _, nufv := range nonUpgradedFeatureVersions {
			nufv.Feature.Namespace.Name = "debian:7"
			assert.Contains(t, jessie.Features, nufv)
		}
		for _, nufv := range nonUpgradedFeatureVersions {
			nufv.Feature.Namespace.Name = "debian:8"
			assert.NotContains(t, jessie.Features, nufv)
		}
	}
}
