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
	"path"
	"runtime"
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/database/pgsql"
	"github.com/coreos/clair/utils/types"
	"github.com/stretchr/testify/assert"

	// Register the required detectors.
	_ "github.com/coreos/clair/worker/detectors/data/docker"
	_ "github.com/coreos/clair/worker/detectors/feature/dpkg"
	_ "github.com/coreos/clair/worker/detectors/namespace/aptsources"
	_ "github.com/coreos/clair/worker/detectors/namespace/osrelease"
)

func TestProcessWithDistUpgrade(t *testing.T) {
	// TODO(Quentin-M): This should not be bound to a single database implementation.
	datastore, err := pgsql.OpenForTest("ProcessWithDistUpgrade", false)
	if err != nil {
		t.Error(err)
		return
	}
	defer datastore.Close()

	_, f, _, _ := runtime.Caller(0)
	path := path.Join(path.Dir(f)) + "/testdata/DistUpgrade/"

	// blank.tar: MAINTAINER Quentin MACHU <quentin.machu.fr>
	// wheezy.tar: FROM debian:wheezy
	// jessie.tar: RUN sed -i "s/precise/trusty/" /etc/apt/sources.list && apt-get update &&
	//             apt-get -y dist-upgrade
	assert.Nil(t, Process(datastore, "blank", "", path+"blank.tar.gz", "Docker"))
	assert.Nil(t, Process(datastore, "wheezy", "blank", path+"wheezy.tar.gz", "Docker"))
	assert.Nil(t, Process(datastore, "jessie", "wheezy", path+"jessie.tar.gz", "Docker"))

	wheezy, err := datastore.FindLayer("wheezy", true, false)
	if assert.Nil(t, err) {
		testDebian7 := database.Namespace{
			Name:    "debian",
			Version: types.NewVersionUnsafe("7"),
		}
		assert.True(t, testDebian7.Equal(wheezy.Namespaces[0]))
		assert.Len(t, wheezy.Features, 52)

		jessie, err := datastore.FindLayer("jessie", true, false)
		if assert.Nil(t, err) {
			testDebian8 := database.Namespace{
				Name:    "debian",
				Version: types.NewVersionUnsafe("8"),
			}
			assert.True(t, testDebian8.Equal(jessie.Namespaces[0]))
			assert.Len(t, jessie.Features, 74)

			// These FeatureVersions haven't been upgraded.
			nonUpgradedFeatureVersions := []database.FeatureVersion{
				{
					Feature: database.Feature{Name: "libtext-wrapi18n-perl"},
					Version: types.NewVersionUnsafe("0.06-7"),
				},
				{
					Feature: database.Feature{Name: "libtext-charwidth-perl"},
					Version: types.NewVersionUnsafe("0.04-7"),
				},
				{
					Feature: database.Feature{Name: "libtext-iconv-perl"},
					Version: types.NewVersionUnsafe("1.7-5"),
				},
				{
					Feature: database.Feature{Name: "mawk"},
					Version: types.NewVersionUnsafe("1.3.3-17"),
				},
				{
					Feature: database.Feature{Name: "insserv"},
					Version: types.NewVersionUnsafe("1.14.0-5"),
				},
				{
					Feature: database.Feature{Name: "db"},
					Version: types.NewVersionUnsafe("5.1.29-5"),
				},
				{
					Feature: database.Feature{Name: "ustr"},
					Version: types.NewVersionUnsafe("1.0.4-3"),
				},
				{
					Feature: database.Feature{Name: "xz-utils"},
					Version: types.NewVersionUnsafe("5.1.1alpha+20120614-2"),
				},
			}

			for _, nufv := range nonUpgradedFeatureVersions {
				nufv.Feature.Namespace.Name = "debian"
				nufv.Feature.Namespace.Version = types.NewVersionUnsafe("7")

				found := false
				for _, fv := range jessie.Features {
					if fv.Feature.Name == nufv.Feature.Name &&
						fv.Feature.Namespace.Equal(nufv.Feature.Namespace) {
						found = true
						break
					}
				}
				assert.Equal(t, true, found, "Jessie layer doesn't have %#v but it should.", nufv)
			}

			for _, nufv := range nonUpgradedFeatureVersions {
				nufv.Feature.Namespace.Name = "debian"
				nufv.Feature.Namespace.Version = types.NewVersionUnsafe("8")

				found := false
				for _, fv := range jessie.Features {
					if fv.Feature.Name == nufv.Feature.Name &&
						fv.Feature.Namespace.Equal(nufv.Feature.Namespace) {
						found = true
						break
					}
				}
				assert.Equal(t, false, found, "Jessie layer has %#v but it shouldn't.", nufv)
			}
		}
	}
}
