package worker

import (
	"path"
	"runtime"
	"testing"

	"github.com/coreos/clair/config"
	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils/types"
	"github.com/stretchr/testify/assert"

	// Register detectors
	_ "github.com/coreos/clair/worker/detectors/data"
	_ "github.com/coreos/clair/worker/detectors/os"
	_ "github.com/coreos/clair/worker/detectors/packages"
)

func TestDistUpgrade(t *testing.T) {
	database.Open(&config.DatabaseConfig{Type: "memstore"})
	defer database.Close()

	_, f, _, _ := runtime.Caller(0)
	path := path.Join(path.Dir(f)) + "/testdata/DistUpgrade/"

	// blank.tar: MAINTAINER Quentin MACHU <quentin.machu.fr>
	// wheezy.tar: FROM debian:wheezy
	// jessie.tar: RUN sed -i "s/precise/trusty/" /etc/apt/sources.list && apt-get update && apt-get -y dist-upgrade
	assert.Nil(t, Process("blank", "", path+"blank.tar.gz", "Docker"))
	assert.Nil(t, Process("wheezy", "blank", path+"wheezy.tar.gz", "Docker"))
	assert.Nil(t, Process("jessie", "wheezy", path+"jessie.tar.gz", "Docker"))

	err := Process("blank", "", path+"blank.tar.gz", "")
	assert.Error(t, err, "could not process a layer which does not have a specified format")

	err = Process("blank", "", path+"blank.tar.gz", "invalid")
	assert.Error(t, err, "could not process a layer which does not have a supported format")

	wheezy, err := database.FindOneLayerByID("wheezy", database.FieldLayerAll)
	if assert.Nil(t, err) {
		assert.Equal(t, "debian:7", wheezy.OS)
		assert.Len(t, wheezy.InstalledPackagesNodes, 52)
		assert.Len(t, wheezy.RemovedPackagesNodes, 0)

		jessie, err := database.FindOneLayerByID("jessie", database.FieldLayerAll)
		if assert.Nil(t, err) {
			assert.Equal(t, "debian:8", jessie.OS)
			assert.Len(t, jessie.InstalledPackagesNodes, 66)
			assert.Len(t, jessie.RemovedPackagesNodes, 44)

			packageNodes, err := jessie.AllPackages()
			if assert.Nil(t, err) {
				// These packages haven't been upgraded
				nonUpgradedPackages := []database.Package{
					database.Package{Name: "libtext-wrapi18n-perl", Version: types.NewVersionUnsafe("0.06-7")},
					database.Package{Name: "libtext-charwidth-perl", Version: types.NewVersionUnsafe("0.04-7")},
					database.Package{Name: "libtext-iconv-perl", Version: types.NewVersionUnsafe("1.7-5")},
					database.Package{Name: "mawk", Version: types.NewVersionUnsafe("1.3.3-17")},
					database.Package{Name: "insserv", Version: types.NewVersionUnsafe("1.14.0-5")},
					database.Package{Name: "db", Version: types.NewVersionUnsafe("5.1.29-5")},
					database.Package{Name: "ustr", Version: types.NewVersionUnsafe("1.0.4-3")},
					database.Package{Name: "xz-utils", Version: types.NewVersionUnsafe("5.1.1alpha+20120614-2")},
				}
				for _, p := range nonUpgradedPackages {
					p.OS = "debian:7"
					assert.Contains(t, packageNodes, p.GetNode(), "Jessie layer doesn't have %s but it should.", p)
				}
				for _, p := range nonUpgradedPackages {
					p.OS = "debian:8"
					assert.NotContains(t, packageNodes, p.GetNode(), "Jessie layer has %s but it shouldn't.", p)
				}
			}
		}
	}
}
