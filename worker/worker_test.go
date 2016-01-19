package worker

import (
	"path"
	"runtime"
	"testing"

	// Register the required detectors.

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/database/pgsql"
	"github.com/coreos/clair/utils/types"
	"github.com/stretchr/testify/assert"

	// Register detectors
	_ "github.com/coreos/clair/worker/detectors/data"
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
		assert.Equal(t, "debian:7", wheezy.Namespace.Name)
		assert.Len(t, wheezy.Features, 52)

		jessie, err := datastore.FindLayer("jessie", true, false)
		if assert.Nil(t, err) {
			assert.Equal(t, "debian:8", jessie.Namespace.Name)
			assert.Len(t, jessie.Features, 74)

			// These FeatureVersions haven't been upgraded.
			nonUpgradedFeatureVersions := []database.FeatureVersion{
				database.FeatureVersion{
					Feature: database.Feature{Name: "libtext-wrapi18n-perl"},
					Version: types.NewVersionUnsafe("0.06-7"),
				},
				database.FeatureVersion{
					Feature: database.Feature{Name: "libtext-charwidth-perl"},
					Version: types.NewVersionUnsafe("0.04-7"),
				},
				database.FeatureVersion{
					Feature: database.Feature{Name: "libtext-iconv-perl"},
					Version: types.NewVersionUnsafe("1.7-5"),
				},
				database.FeatureVersion{
					Feature: database.Feature{Name: "mawk"},
					Version: types.NewVersionUnsafe("1.3.3-17"),
				},
				database.FeatureVersion{
					Feature: database.Feature{Name: "insserv"},
					Version: types.NewVersionUnsafe("1.14.0-5"),
				},
				database.FeatureVersion{
					Feature: database.Feature{Name: "db"},
					Version: types.NewVersionUnsafe("5.1.29-5"),
				},
				database.FeatureVersion{
					Feature: database.Feature{Name: "ustr"},
					Version: types.NewVersionUnsafe("1.0.4-3"),
				},
				database.FeatureVersion{
					Feature: database.Feature{Name: "xz-utils"},
					Version: types.NewVersionUnsafe("5.1.1alpha+20120614-2"),
				},
			}

			for _, nufv := range nonUpgradedFeatureVersions {
				nufv.Feature.Namespace.Name = "debian:7"

				found := false
				for _, fv := range jessie.Features {
					if fv.Feature.Name == nufv.Feature.Name &&
						fv.Feature.Namespace.Name == nufv.Feature.Namespace.Name &&
						fv.Version == nufv.Version {
						found = true
						break
					}
				}
				assert.Equal(t, true, found, "Jessie layer doesn't have %#v but it should.", nufv)
			}

			for _, nufv := range nonUpgradedFeatureVersions {
				nufv.Feature.Namespace.Name = "debian:8"

				found := false
				for _, fv := range jessie.Features {
					if fv.Feature.Name == nufv.Feature.Name &&
						fv.Feature.Namespace.Name == nufv.Feature.Namespace.Name &&
						fv.Version == nufv.Version {
						found = true
						break
					}
				}
				assert.Equal(t, false, found, "Jessie layer has %#v but it shouldn't.", nufv)
			}
		}
	}
}
