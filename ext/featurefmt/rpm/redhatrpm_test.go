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

package rpm

import (
	"testing"

	"github.com/quay/clair/v3/database"
	"github.com/quay/clair/v3/ext/featurefmt"
	"github.com/quay/clair/v3/ext/featurefmt/rpm/contentmanifest"
	"github.com/quay/clair/v3/ext/versionfmt/rpm"
)

type FakeUpdater struct{}

func (updater *FakeUpdater) Update() error {
	return nil
}

func (updater *FakeUpdater) Get(repositories []string) ([]string, error) {
	CPEs := []string{}
	fakeMapping := map[string][]string{
		"content-set-1": []string{
			"cpe:/o:redhat:enterprise_linux:7::client",
		},
		"content-set-2": []string{
			"cpe:/o:redhat:enterprise_linux:7::server",
		},
	}
	for _, repo := range repositories {
		if repoCPEs, ok := fakeMapping[repo]; ok {
			CPEs = append(CPEs, repoCPEs...)
		}
	}
	return CPEs, nil
}

// FakeContainerApiCpeNamespaceFetcher is a mock CPE fetcher
type FakeContainerApiCpeNamespaceFetcher struct{}

func (fetcher *FakeContainerApiCpeNamespaceFetcher) GetCPEs(nvr, arch string) ([]string, error) {
	if nvr == "rh-pkg-1-1" && arch == "x86_64" {
		return []string{
			"cpe:/o:redhat:enterprise_linux:8::computenode",
			"cpe:/o:redhat:enterprise_linux:8::baseos",
		}, nil
	}
	return []string{}, nil
}

func TestRpmFeatureDetectionWithCPE(t *testing.T) {
	for _, test := range []featurefmt.TestCase{
		{
			"rpm with valid cpes",
			map[string]string{
				"var/lib/rpm/Packages":               "rpm/testdata/valid",
				"root/buildinfo/Dockerfile-name-1-1": "rpm/testdata/Dockerfile-name-1-1",
			},
			[]database.LayerFeature{
				{
					Feature:            NamespaceHolderPackage,
					PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:8::computenode", VersionFormat: "rpm"},
				},
				{
					Feature:            NamespaceHolderPackage,
					PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:8::baseos", VersionFormat: "rpm"},
				},
				{
					Feature:            database.Feature{Name: "filesystem", Version: "3.2-18.el7", VersionFormat: "rpm", Type: "binary"},
					PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:8::computenode", VersionFormat: "rpm"},
				},
				{
					Feature:            database.Feature{Name: "filesystem", Version: "3.2-18.el7", VersionFormat: "rpm", Type: "binary"},
					PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:8::baseos", VersionFormat: "rpm"},
				},
				{
					Feature:            database.Feature{Name: "filesystem", Version: "3.2-18.el7", VersionFormat: "rpm", Type: "source"},
					PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:8::computenode", VersionFormat: "rpm"},
				},
				{
					Feature:            database.Feature{Name: "filesystem", Version: "3.2-18.el7", VersionFormat: "rpm", Type: "source"},
					PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:8::baseos", VersionFormat: "rpm"},
				},
				{
					Feature:            database.Feature{Name: "centos-release", Version: "7-1.1503.el7.centos.2.8", VersionFormat: "rpm", Type: "binary"},
					PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:8::computenode", VersionFormat: "rpm"},
				},
				{
					Feature:            database.Feature{Name: "centos-release", Version: "7-1.1503.el7.centos.2.8", VersionFormat: "rpm", Type: "binary"},
					PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:8::baseos", VersionFormat: "rpm"},
				},
				{
					Feature:            database.Feature{Name: "centos-release", Version: "7-1.1503.el7.centos.2.8", VersionFormat: "rpm", Type: "source"},
					PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:8::computenode", VersionFormat: "rpm"},
				},
				{
					Feature:            database.Feature{Name: "centos-release", Version: "7-1.1503.el7.centos.2.8", VersionFormat: "rpm", Type: "source"},
					PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:8::baseos", VersionFormat: "rpm"},
				},
			},
		},
		{
			"rpm with unknown cpes",
			map[string]string{
				"var/lib/rpm/Packages": "rpm/testdata/valid",
			},
			[]database.LayerFeature{
				{Feature: database.Feature{Name: "filesystem", Version: "3.2-18.el7", VersionFormat: "rpm", Type: "binary"}},
				{Feature: database.Feature{Name: "centos-release", Version: "7-1.1503.el7.centos.2.8", VersionFormat: "rpm", Type: "binary"}},
				{Feature: database.Feature{Name: "centos-release", Version: "7-1.1503.el7.centos.2.8", VersionFormat: "rpm", Type: "source"}},
				{Feature: database.Feature{Name: "filesystem", Version: "3.2-18.el7", VersionFormat: "rpm", Type: "source"}},
			},
		},
		{
			"empty rpm list - just feature with namespaces",
			map[string]string{
				"root/buildinfo/Dockerfile-name-1-1": "rpm/testdata/Dockerfile-name-1-1",
			},
			[]database.LayerFeature{
				{
					Feature:            NamespaceHolderPackage,
					PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:8::computenode", VersionFormat: "rpm"},
				},
				{
					Feature:            NamespaceHolderPackage,
					PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:8::baseos", VersionFormat: "rpm"},
				},
			},
		},
		{
			"Embedded content-sets",
			map[string]string{
				"root/buildinfo/content_manifests/foo-1.1-2.json": "rpm/testdata/foo-1.1-2.json",
				"var/lib/rpm/Packages":                            "rpm/testdata/valid",
			},
			[]database.LayerFeature{
				{
					Feature:            NamespaceHolderPackage,
					PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:7::client", VersionFormat: "rpm"},
				},
				{
					Feature:            NamespaceHolderPackage,
					PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:7::server", VersionFormat: "rpm"},
				},
				{
					Feature:            database.Feature{Name: "filesystem", Version: "3.2-18.el7", VersionFormat: "rpm", Type: "binary"},
					PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:7::client", VersionFormat: "rpm"},
				},
				{
					Feature:            database.Feature{Name: "filesystem", Version: "3.2-18.el7", VersionFormat: "rpm", Type: "binary"},
					PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:7::server", VersionFormat: "rpm"},
				},
				{
					Feature:            database.Feature{Name: "filesystem", Version: "3.2-18.el7", VersionFormat: "rpm", Type: "source"},
					PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:7::client", VersionFormat: "rpm"},
				},
				{
					Feature:            database.Feature{Name: "filesystem", Version: "3.2-18.el7", VersionFormat: "rpm", Type: "source"},
					PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:7::server", VersionFormat: "rpm"},
				},
				{
					Feature:            database.Feature{Name: "centos-release", Version: "7-1.1503.el7.centos.2.8", VersionFormat: "rpm", Type: "binary"},
					PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:7::client", VersionFormat: "rpm"},
				},
				{
					Feature:            database.Feature{Name: "centos-release", Version: "7-1.1503.el7.centos.2.8", VersionFormat: "rpm", Type: "binary"},
					PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:7::server", VersionFormat: "rpm"},
				},
				{
					Feature:            database.Feature{Name: "centos-release", Version: "7-1.1503.el7.centos.2.8", VersionFormat: "rpm", Type: "source"},
					PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:7::client", VersionFormat: "rpm"},
				},
				{
					Feature:            database.Feature{Name: "centos-release", Version: "7-1.1503.el7.centos.2.8", VersionFormat: "rpm", Type: "source"},
					PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:7::server", VersionFormat: "rpm"},
				},
			},
		},
	} {
		featurefmt.RunTest(
			t,
			test,
			lister{
				&FakeContainerApiCpeNamespaceFetcher{},
				&contentmanifest.RepoCPEMapping{
					&FakeUpdater{},
				},
			},
			rpm.ParserName)
	}
}
