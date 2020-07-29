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

package redhat

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/quay/clair/v3/database"
	log "github.com/sirupsen/logrus"
)

const (
	TestLastAdvisoryDate = "2019-11-01"
)

var LastAdvisoryDate = "2000-01-01"

func GetLastAdvisoryDate() string {
	return LastAdvisoryDate
}

func SetLastAdvisoryDate(d string) {
	LastAdvisoryDate = d
}

func TestIsNewOrUpdatedManifestEntry(t *testing.T) {

	manifestEntry1 := ManifestEntry{
		"RHEL8/ansible-2.8.oval.xml.bz2", "14a04f048080a246ef4e1d1c76e5beec12d16cbfd8013235f0ff2f88e4d78aed", 3755}
	manifestEntry2 := ManifestEntry{
		"RHEL8/ansible-2.8.oval.xml.bz2", "320eeb4984a0678e4fa9a3f8421b87f2a57a2922cd4e3f582eb7cc735239ce72", 3755}
	type args struct {
		manifestEntry ManifestEntry
		datastore     database.Datastore
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"1", args{manifestEntry1, newmockDatastore()}, false},
		{"2", args{manifestEntry2, newmockDatastore()}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNewOrUpdatedManifestEntry(tt.args.manifestEntry, tt.args.datastore); got != tt.want {
				t.Errorf("IsNewOrUpdatedManifestEntry() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsArchSupported(t *testing.T) {
	type args struct {
		arch string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"1", args{"x86_64"}, true},
		{"2", args{"noarch"}, true},
		{"3", args{"ppcle64"}, false},
		{"4", args{"x86_64|ppcle64"}, true},
		{"5", args{"aarch64|ppc64le|s390x|x86_64"}, true},
		{"6", args{"aarch64|x86_64|ppc64le|s390x"}, true},
		{"7", args{"ppc64le|s390x"}, false},
		{"8", args{""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// debug
			log.Info(fmt.Sprintf("IsArchSupported(%s)", tt.args.arch))
			if got := IsArchSupported(tt.args.arch); got != tt.want {
				t.Errorf("IsArchSupported(%v) = %v, want %v", tt.args.arch, got, tt.want)
			}
		})
	}
}

func TestIsRelevantCriterion(t *testing.T) {
	type args struct {
		criterion OvalV2Criterion
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"1", args{OvalV2Criterion{Comment: "softhsm-devel is earlier than 0:2.4.0-2.module+el8.1.0+4098+f286395e"}}, true},
		{"2", args{OvalV2Criterion{Comment: "Module idm:DL1 is enabled"}}, true},
		{"3", args{OvalV2Criterion{Comment: "Red Hat Enterprise Linux must be installed"}}, false},
		{"4", args{OvalV2Criterion{Comment: "softhsm-devel is signed with Red Hat redhatrelease2 key"}}, false},
		{"5", args{OvalV2Criterion{Comment: ""}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// debug
			log.Info(fmt.Sprintf("IsRelevantCriterion(%s)", tt.args.criterion))
			if got := IsRelevantCriterion(tt.args.criterion); got != tt.want {
				t.Errorf("IsRelevantCriterion(%v) = %v, want %v", tt.args.criterion, got, tt.want)
			}
		})
	}
}

func TestIsSupportedDefinitionType(t *testing.T) {
	type args struct {
		arch string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"1", args{"patch"}, true},
		{"2", args{"vulnerability"}, false},
		{"3", args{"miscellaneous"}, false},
		{"4", args{"other"}, false},
		{"5", args{""}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// debug
			log.Info(fmt.Sprintf("IsSupportedDefinitionType(%s)", tt.args.arch))
			if got := IsSupportedDefinitionType(tt.args.arch); got != tt.want {
				t.Errorf("IsSupportedDefinitionType(%v) = %v, want %v", tt.args.arch, got, tt.want)
			}
			// debug
			log.Info(fmt.Sprintf("!IsSupportedDefinitionType(%s)", tt.args.arch))
			if got := !IsSupportedDefinitionType(tt.args.arch); got != !tt.want {
				t.Errorf("!IsSupportedDefinitionType(%v) = %v, want %v", tt.args.arch, got, !tt.want)
			}
		})
	}
}

func TestGetUnprocessedAdvisories(t *testing.T) {
	pwd, _ := os.Getwd()
	xmlFilePath := pwd + "/testdata/v2/ansible-2.8.oval.xml"
	xmlContent, err := ioutil.ReadFile(xmlFilePath)
	if err != nil {
		log.Fatal("error reading " + xmlFilePath)
	}
	ovalDoc := OvalV2Document{}
	err = xml.Unmarshal([]byte(xmlContent), &ovalDoc)
	if err != nil {
		// log error and continue
		log.Fatal(err)
	}

	type args struct {
		ovalDoc   OvalV2Document
		sinceDate string
	}
	tests := []struct {
		name      string
		args      args
		wantCount int
		wantErr   bool
	}{
		{"1", args{ovalDoc, "2020-01-22"}, 1, false},
		{"2", args{ovalDoc, "2019-10-25"}, 2, false},
		{"3", args{ovalDoc, "2019-10-23"}, 3, false},
		{"4", args{ovalDoc, "2019-08-21"}, 4, false},
		{"5", args{ovalDoc, "2019-07-01"}, 5, false},
	}
	for _, tt := range tests {
		SetLastAdvisoryDate(tt.args.sinceDate)
		t.Run(tt.name, func(t *testing.T) {
			got, err := ProcessAdvisoriesSinceLastDbUpdate(tt.args.ovalDoc, newmockDatastore())
			if (err != nil) != tt.wantErr {
				t.Errorf("ProcessAdvisoriesSinceLastDbUpdate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantCount != len(got) {
				t.Errorf("ProcessAdvisoriesSinceLastDbUpdate() = %v, want %v", len(got), tt.wantCount)
			}
		})
	}
}

func TestDbLookupLastAdvisoryDate(t *testing.T) {
	type args struct {
		datastore database.Datastore
		sinceDate string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"1", args{newmockDatastore(), TestLastAdvisoryDate}, TestLastAdvisoryDate},
		{"2", args{newmockDatastore(), "2019-07-01"}, "2019-07-01"},
		{"3", args{newmockDatastore(), "2019-11-04"}, "2019-11-04"},
		{"4", args{newmockDatastore(), ""}, "1970-01-01"},
	}
	for _, tt := range tests {
		SetLastAdvisoryDate(tt.args.sinceDate)
		t.Run(tt.name, func(t *testing.T) {
			if got := DbLookupLastAdvisoryDate(tt.args.datastore); got != tt.want {
				t.Errorf("DbLookupLastAdvisoryDate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFetchPulpManifest(t *testing.T) {
	pwd, _ := os.Getwd()
	filePath := pwd + "/testdata/v2/PULP_MANIFEST"
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatal("error reading " + filePath)
	} else {
		log.Debug("found " + filePath + ": " + string(content))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(string(content)))
	}))
	defer srv.Close()
	type args struct {
		pulpManifestURL string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"1", args{string(srv.URL)}, string(content), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FetchPulpManifest(tt.args.pulpManifestURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("FetchPulpManifest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("FetchPulpManifest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReadBzipOvalFile(t *testing.T) {
	pwd, _ := os.Getwd()
	// bzip-compressed file (used for the httptest download endpoint)
	bzipFilePath := pwd + "/testdata/v2/ansible-2.8.oval.xml.bz2"
	bzipContent, err := ioutil.ReadFile(bzipFilePath)
	// uncompressed xml file (used for the test result comparison)
	xmlFilePath := pwd + "/testdata/v2/ansible-2.8.oval.xml"
	xmlContent, err := ioutil.ReadFile(xmlFilePath)
	if err != nil {
		log.Fatal("error reading " + xmlFilePath)
	} else {
		log.Debug("found " + xmlFilePath + ": " + string(xmlContent))
	}
	// httptest provides the bzip file download endpoint
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(string(bzipContent)))
	}))
	defer srv1.Close()
	// httptest provides the non-bzip file download endpoint
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(string("ABCD1234")))
	}))
	defer srv2.Close()
	type args struct {
		bzipOvalFile string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"given valid bzip2 file, expect success", args{string(srv1.URL)}, string(xmlContent), false},
		{"given non-bzip2 file, expect error", args{string(srv2.URL)}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadBzipOvalFile(tt.args.bzipOvalFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadBzipOvalFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ReadBzipOvalFile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCpeNamesFromAffectedCpeList(t *testing.T) {
	pwd, _ := os.Getwd()
	xmlFilePath := pwd + "/testdata/v2/ansible-1.x.oval.xml"
	xmlContent, err := ioutil.ReadFile(xmlFilePath)
	if err != nil {
		log.Fatal("error reading " + xmlFilePath)
	} else {
		log.Debug("found " + xmlFilePath + ": " + string(xmlContent))
	}
	ovalDoc := OvalV2Document{}
	err = xml.Unmarshal([]byte(xmlContent), &ovalDoc)
	if err != nil {
		// log error and continue
		log.Fatal(err)
	}
	type args struct {
		affectedCpeList OvalV2Cpe
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			"Two cpes",
			args{ovalDoc.DefinitionSet.Definitions[0].Metadata.Advisory.AffectedCpeList},
			[]string{
				"cpe:/a:redhat:ansible_engine:2.8",
				"cpe:/a:redhat:ansible_engine:2.8::el8",
			},
			false,
		},
		{
			"With one empty cpe",
			args{ovalDoc.DefinitionSet.Definitions[1].Metadata.Advisory.AffectedCpeList},
			[]string{
				"cpe:/a:redhat:ansible_engine:2.8",
				"cpe:/a:redhat:ansible_engine:2.8::el8",
			},
			false,
		},
		{
			"No cpe (unparseable)",
			args{ovalDoc.DefinitionSet.Definitions[2].Metadata.Advisory.AffectedCpeList},
			[]string{},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCpeNamesFromAffectedCpeList(tt.args.affectedCpeList)
			if err != nil {
				if (err != nil) != tt.wantErr {
					t.Errorf("ParseCpeNamesFromAffectedCpeList() error = %v, wantErr %v", err, tt.wantErr)
				}
				// expected error, no need to continue
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseCpeNamesFromAffectedCpeList() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsSignificantSeverity(t *testing.T) {
	type args struct {
		severity string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"None", args{"None"}, false},
		{"Low", args{"Low"}, true},
		{"Moderate", args{"Moderate"}, true},
		{"Important", args{"Important"}, true},
		{"Critical", args{"Critical"}, true},
		{"Unknown", args{"Unknown"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSignificantSeverity(tt.args.severity); got != tt.want {
				t.Errorf("IsSignificantSeverity(%s->%s) = %v, want %v",
					tt.args.severity,
					strings.Title(tt.args.severity),
					got,
					tt.want)
			}
			// test as all uppercase
			if got := IsSignificantSeverity(strings.ToUpper(tt.args.severity)); got != tt.want {
				t.Errorf("IsSignificantSeverity(%s->%s) = %v, want %v",
					strings.ToUpper(tt.args.severity),
					strings.Title(strings.ToUpper(tt.args.severity)),
					got,
					tt.want)
			}
			// test as all lowercase
			if got := IsSignificantSeverity(strings.ToLower(tt.args.severity)); got != tt.want {
				t.Errorf("IsSignificantSeverity(%s->%s) = %v, want %v",
					strings.ToLower(tt.args.severity),
					strings.Title(strings.ToLower(tt.args.severity)),
					got,
					tt.want)
			}
		})
	}
}

func TestGetSeverity(t *testing.T) {
	type args struct {
		severity string
	}
	tests := []struct {
		name string
		args args
		want database.Severity
	}{
		{"None", args{"None"}, database.NegligibleSeverity},
		{"Low", args{"Low"}, database.LowSeverity},
		{"Moderate", args{"Moderate"}, database.MediumSeverity},
		{"Important", args{"Important"}, database.HighSeverity},
		{"Critical", args{"Critical"}, database.CriticalSeverity},
		{"Unknown", args{"Unknown"}, database.UnknownSeverity},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetSeverity(tt.args.severity); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetSeverity(%s->%s) = %v, want %v",
					tt.args.severity,
					strings.Title(tt.args.severity),
					got,
					tt.want)
			}
			// test as all uppercase
			if got := GetSeverity(tt.args.severity); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetSeverity(%s->%s) = %v, want %v",
					tt.args.severity,
					strings.Title(strings.ToUpper(tt.args.severity)),
					got,
					tt.want)
			}
			// test as all lowercase
			if got := GetSeverity(tt.args.severity); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetSeverity(%s->%s) = %v, want %v",
					tt.args.severity,
					strings.Title(strings.ToLower(tt.args.severity)),
					got,
					tt.want)
			}
		})
	}
}

func TestParsedNvrasContains(t *testing.T) {
	type args struct {
		parsedNvras []ParsedRmpNvra
		nvra        ParsedRmpNvra
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"1", args{[]ParsedRmpNvra{
			ParsedRmpNvra{Name: "name1", Evr: "evr1", Arch: "arch1"},
		},
			ParsedRmpNvra{Name: "name1", Evr: "evr1", Arch: "arch1"}},
			true,
		},
		{"2", args{[]ParsedRmpNvra{
			ParsedRmpNvra{Name: "name1", Evr: "evr1", Arch: "arch1"},
		},
			ParsedRmpNvra{Name: "name1", Evr: "evr1", Arch: "arch2"}},
			false,
		},
		{"3", args{[]ParsedRmpNvra{
			ParsedRmpNvra{Name: "name1", Evr: "evr1", Arch: "arch1"},
			ParsedRmpNvra{Name: "name1", Evr: "evr1", Arch: "arch2"},
			ParsedRmpNvra{Name: "name1", Evr: "evr1", Arch: "arch3"},
		},
			ParsedRmpNvra{Name: "name1", Evr: "evr1", Arch: "arch1"}},
			true},
		{"4", args{[]ParsedRmpNvra{
			ParsedRmpNvra{Name: "name1", Evr: "evr1", Arch: "arch1"},
			ParsedRmpNvra{Name: "name2", Evr: "evr1", Arch: "arch1"},
			ParsedRmpNvra{Name: "name3", Evr: "evr1", Arch: "arch1"},
		},
			ParsedRmpNvra{Name: "name2", Evr: "evr1", Arch: "arch1"}},
			true},
		{"5", args{[]ParsedRmpNvra{
			ParsedRmpNvra{Name: "name1", Evr: "evr1", Arch: "arch1"},
			ParsedRmpNvra{Name: "name1", Evr: "evr2", Arch: "arch1"},
			ParsedRmpNvra{Name: "name1", Evr: "evr3", Arch: "arch1"},
		},
			ParsedRmpNvra{Name: "name1", Evr: "evr3", Arch: "arch1"}},
			true},
		{"6", args{[]ParsedRmpNvra{
			ParsedRmpNvra{Name: "name1", Evr: "evr1", Arch: "arch1"},
			ParsedRmpNvra{Name: "name1", Evr: "evr2", Arch: "arch1"},
			ParsedRmpNvra{Name: "name1", Evr: "evr3", Arch: "arch1"},
		},
			ParsedRmpNvra{Name: "name1", Evr: "evr4", Arch: "arch1"}},
			false},
		{"7", args{[]ParsedRmpNvra{
			ParsedRmpNvra{Name: "name1", Evr: "evr1", Arch: "arch1"},
			ParsedRmpNvra{Name: "name1", Evr: "evr2", Arch: "arch1"},
			ParsedRmpNvra{Name: "name1", Evr: "evr3", Arch: "arch1"},
		},
			ParsedRmpNvra{Name: "name2", Evr: "evr2", Arch: "arch1"}},
			false},
		{"8", args{[]ParsedRmpNvra{},
			ParsedRmpNvra{Name: "name1", Evr: "evr1", Arch: "arch1"}},
			false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// debug
			log.Info(fmt.Sprintf("ParsedNvrasContains(%s, %s)", tt.args.parsedNvras, tt.args.nvra))
			if got := ParsedNvrasContains(tt.args.parsedNvras, tt.args.nvra); got != tt.want {
				t.Errorf("ParsedNvrasContains(%v, %v) = %v, want %v", tt.args.parsedNvras, tt.args.nvra, got, tt.want)
			}
		})
	}
}

func TestParseRhsaName(t *testing.T) {
	type args struct {
		advisoryDefinition ParsedAdvisory
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			"1",
			args{
				ParsedAdvisory{Metadata: OvalV2Metadata{Title: "RHSA-2013:0149: flash-plugin security update (Critical)", Reference: []OvalV2Reference{{RefID: "RHSA-2013:0149"}}}},
			},
			"RHSA-2013:0149",
		},
		{
			"2",
			args{
				ParsedAdvisory{Metadata: OvalV2Metadata{Title: "RHSA-2013:0149: flash-plugin security update (Critical)", Reference: []OvalV2Reference{{RefID: ""}}}},
			},
			"RHSA-2013:0149",
		},
		{
			"3",
			args{
				ParsedAdvisory{Metadata: OvalV2Metadata{Title: "RHSA-2013:0149: flash-plugin security update (Critical)", Reference: []OvalV2Reference{}}},
			},
			"RHSA-2013:0149",
		},
		{
			"4",
			args{
				ParsedAdvisory{Metadata: OvalV2Metadata{Title: "", Reference: []OvalV2Reference{{RefID: ""}}}},
			},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseRhsaName(tt.args.advisoryDefinition); got != tt.want {
				t.Errorf("ParseRhsaName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCriteriaForModuleNamespaces(t *testing.T) {
	type args struct {
		criteria OvalV2Criteria
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			"One Module",
			args{
				OvalV2Criteria{Criterion: []OvalV2Criterion{{Comment: "Module nodejs:12 is enabled", TestRef: "oval:com.redhat.rhea:tst:20200330015"}}},
			},
			[]string{"nodejs:12"},
		},
		{
			"Non-Module",
			args{
				OvalV2Criteria{Criterion: []OvalV2Criterion{{Comment: "vim-filesystem is earlier than vim-filesystem-2:7.4.629-2.el7.x86_64", TestRef: "oval:com.redhat.rhsa:tst:20162972001"}}},
			},
			[]string{},
		},
		{
			"Three Modules",
			args{
				OvalV2Criteria{
					Criterion: []OvalV2Criterion{
						{Comment: "Module nodejs:12 is enabled", TestRef: "oval:com.redhat.rhea:tst:20200330015"},
						{Comment: "Module idm:DL1 is enabled", TestRef: "oval:com.redhat.rhea:tst:20200330015"},
						{Comment: "Module container-tools:rhel8 is enabled", TestRef: "oval:com.redhat.rhea:tst:20200330015"},
					},
				},
			},
			[]string{"nodejs:12", "idm:DL1", "container-tools:rhel8"},
		},
		{
			"Empty Criteria",
			args{
				OvalV2Criteria{},
			},
			[]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseCriteriaForModuleNamespaces(tt.args.criteria)
			if len(got) == 0 {
				if len(tt.want) != 0 {
					t.Errorf("ParseCriteriaForModuleNamespaces() = %v, want %v", got, tt.want)
				}
			} else if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseCriteriaForModuleNamespaces() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVulnerabilityContainsFeature(t *testing.T) {
	type args struct {
		vulnerability     database.VulnerabilityWithAffected
		comparisonFeature database.AffectedFeature
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			"found in one feature",
			args{
				database.VulnerabilityWithAffected{
					Vulnerability: database.Vulnerability{
						Name: "vuln one",
					},
					Affected: []database.AffectedFeature{
						{
							FeatureName:     "first-feature-name",
							AffectedVersion: "v.0.0.1",
							FixedInVersion:  "v.0.0.1",
							FeatureType:     "first.feature.type",
						},
					},
				},
				database.AffectedFeature{
					FeatureName:     "first-feature-name",
					AffectedVersion: "v.0.0.1",
					FixedInVersion:  "v.0.0.1",
					FeatureType:     "first.feature.type",
				},
			},
			true,
		},
		{
			"not found in one feature",
			args{
				database.VulnerabilityWithAffected{
					Vulnerability: database.Vulnerability{
						Name: "vuln one",
					},
					Affected: []database.AffectedFeature{
						{
							FeatureName:     "first-feature-name",
							AffectedVersion: "v.0.0.1",
							FixedInVersion:  "v.0.0.1",
							FeatureType:     "first.feature.type",
						},
					},
				},
				database.AffectedFeature{
					FeatureName:     "second-feature-name",
					AffectedVersion: "v.0.0.2",
					FixedInVersion:  "v.0.0.2",
					FeatureType:     "second.feature.type",
				},
			},
			false,
		},
		{
			"found in three features",
			args{
				database.VulnerabilityWithAffected{
					Vulnerability: database.Vulnerability{
						Name: "vuln one",
					},
					Affected: []database.AffectedFeature{
						{
							FeatureName:     "first-feature-name",
							AffectedVersion: "v.0.0.1",
							FixedInVersion:  "v.0.0.1",
							FeatureType:     "first.feature.type",
						},
						{
							FeatureName:     "second-feature-name",
							AffectedVersion: "v.0.0.2",
							FixedInVersion:  "v.0.0.2",
							FeatureType:     "second.feature.type",
						},
						{
							FeatureName:     "third-feature-name",
							AffectedVersion: "v.0.0.3",
							FixedInVersion:  "v.0.0.3",
							FeatureType:     "third.feature.type",
						},
					},
				},
				database.AffectedFeature{
					FeatureName:     "second-feature-name",
					AffectedVersion: "v.0.0.2",
					FixedInVersion:  "v.0.0.2",
					FeatureType:     "second.feature.type",
				},
			},
			true,
		},
		{
			"not found in three features",
			args{
				database.VulnerabilityWithAffected{
					Vulnerability: database.Vulnerability{
						Name: "vuln one",
					},
					Affected: []database.AffectedFeature{
						{
							FeatureName:     "first-feature-name",
							AffectedVersion: "v.0.0.1",
							FixedInVersion:  "v.0.0.1",
							FeatureType:     "first.feature.type",
						},
						{
							FeatureName:     "second-feature-name",
							AffectedVersion: "v.0.0.2",
							FixedInVersion:  "v.0.0.2",
							FeatureType:     "second.feature.type",
						},
						{
							FeatureName:     "third-feature-name",
							AffectedVersion: "v.0.0.3",
							FixedInVersion:  "v.0.0.3",
							FeatureType:     "third.feature.type",
						},
					},
				},
				// imperfect match
				database.AffectedFeature{
					FeatureName:     "second-feature-name",
					AffectedVersion: "v.0.0.4",
					FixedInVersion:  "v.0.0.4",
					FeatureType:     "second.feature.type",
				},
			},
			false,
		},
		{
			"not found in zero features",
			args{
				database.VulnerabilityWithAffected{
					Vulnerability: database.Vulnerability{
						Name: "vuln one",
					},
					Affected: []database.AffectedFeature{},
				},
				database.AffectedFeature{
					FeatureName:     "first-feature-name",
					AffectedVersion: "v.0.0.1",
					FixedInVersion:  "v.0.0.1",
					FeatureType:     "first.feature.type",
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VulnerabilityContainsFeature(tt.args.vulnerability, tt.args.comparisonFeature); got != tt.want {
				t.Errorf("VulnerabilityContainsFeature() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetPendingVulnerabilitySliceIndex(t *testing.T) {
	type args struct {
		vulnSet    []database.VulnerabilityWithAffected
		lookupVuln database.VulnerabilityWithAffected
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			"found among one vuln",
			args{
				[]database.VulnerabilityWithAffected{
					{
						Vulnerability: database.Vulnerability{
							Name: "vuln one",
						},
					},
				},
				database.VulnerabilityWithAffected{
					Vulnerability: database.Vulnerability{
						Name: "vuln one",
					},
				},
			},
			0,
		},
		{
			"not found among one vuln",
			args{
				[]database.VulnerabilityWithAffected{
					{
						Vulnerability: database.Vulnerability{
							Name: "vuln one",
						},
					},
				},
				database.VulnerabilityWithAffected{
					Vulnerability: database.Vulnerability{
						Name: "vuln two",
					},
				},
			},
			-1,
		},
		{
			"found among three vulns",
			args{
				[]database.VulnerabilityWithAffected{
					{
						Vulnerability: database.Vulnerability{
							Name: "vuln one",
						},
					},
					{
						Vulnerability: database.Vulnerability{
							Name: "vuln two",
						},
					},
					{
						Vulnerability: database.Vulnerability{
							Name: "vuln three",
						},
					},
				},
				database.VulnerabilityWithAffected{
					Vulnerability: database.Vulnerability{
						Name: "vuln two",
					},
				},
			},
			1,
		},
		{
			"not found among three vulns",
			args{
				[]database.VulnerabilityWithAffected{
					{
						Vulnerability: database.Vulnerability{
							Name: "vuln one",
						},
					},
					{
						Vulnerability: database.Vulnerability{
							Name: "vuln two",
						},
					},
					{
						Vulnerability: database.Vulnerability{
							Name: "vuln three",
						},
					},
				},
				database.VulnerabilityWithAffected{
					Vulnerability: database.Vulnerability{
						Name: "vuln four",
					},
				},
			},
			-1,
		},
		{
			"not found among zero vulns",
			args{
				[]database.VulnerabilityWithAffected{},
				database.VulnerabilityWithAffected{
					Vulnerability: database.Vulnerability{
						Name: "vuln four",
					},
				},
			},
			-1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetPendingVulnerabilitySliceIndex(tt.args.vulnSet, tt.args.lookupVuln); got != tt.want {
				t.Errorf("GetPendingVulnerabilitySliceIndex() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMergeVulnerabilityFeature(t *testing.T) {
	type args struct {
		sourceVuln database.VulnerabilityWithAffected
		targetVuln database.VulnerabilityWithAffected
	}
	tests := []struct {
		name string
		args args
		want database.VulnerabilityWithAffected
	}{
		{
			"one merged from two sets of three features",
			args{
				database.VulnerabilityWithAffected{
					Vulnerability: database.Vulnerability{
						Name: "vuln one",
					},
					Affected: []database.AffectedFeature{
						{
							FeatureName:     "first-feature-name",
							AffectedVersion: "v.0.0.1",
							FixedInVersion:  "v.0.0.1",
							FeatureType:     "first.feature.type",
						},
						{
							FeatureName:     "second-feature-name",
							AffectedVersion: "v.0.0.2",
							FixedInVersion:  "v.0.0.2",
							FeatureType:     "second.feature.type",
						},
						{
							FeatureName:     "third-feature-name",
							AffectedVersion: "v.0.0.3",
							FixedInVersion:  "v.0.0.3",
							FeatureType:     "third.feature.type",
						},
					},
				},
				database.VulnerabilityWithAffected{
					Vulnerability: database.Vulnerability{
						Name: "vuln one",
					},
					Affected: []database.AffectedFeature{
						{
							FeatureName:     "second-feature-name",
							AffectedVersion: "v.0.0.2",
							FixedInVersion:  "v.0.0.2",
							FeatureType:     "second.feature.type",
						},
						{
							FeatureName:     "third-feature-name",
							AffectedVersion: "v.0.0.3",
							FixedInVersion:  "v.0.0.3",
							FeatureType:     "third.feature.type",
						},
						{
							FeatureName:     "fourth-feature-name",
							AffectedVersion: "v.0.0.4",
							FixedInVersion:  "v.0.0.4",
							FeatureType:     "fourth.feature.type",
						},
					},
				},
			},
			database.VulnerabilityWithAffected{
				Vulnerability: database.Vulnerability{
					Name: "vuln one",
				},
				Affected: []database.AffectedFeature{
					{
						FeatureName:     "second-feature-name",
						AffectedVersion: "v.0.0.2",
						FixedInVersion:  "v.0.0.2",
						FeatureType:     "second.feature.type",
					},
					{
						FeatureName:     "third-feature-name",
						AffectedVersion: "v.0.0.3",
						FixedInVersion:  "v.0.0.3",
						FeatureType:     "third.feature.type",
					},
					{
						FeatureName:     "fourth-feature-name",
						AffectedVersion: "v.0.0.4",
						FixedInVersion:  "v.0.0.4",
						FeatureType:     "fourth.feature.type",
					},
					// additional source features will be apppended to the end of the target slice
					{
						FeatureName:     "first-feature-name",
						AffectedVersion: "v.0.0.1",
						FixedInVersion:  "v.0.0.1",
						FeatureType:     "first.feature.type",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MergeVulnerabilityFeature(tt.args.sourceVuln, tt.args.targetVuln); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MergeVulnerabilityFeature() = %v, want %v", got, tt.want)
			}
		})
	}
}

// (also tests MergeVulnerabilities)
func TestCollectVulnsForAdvisory(t *testing.T) {
	pwd, _ := os.Getwd()
	fileCollectVulnsTestDataRhel7 := pwd + "/testdata/v2/collect-vulns-rhel7.xml"
	xmlCollectVulnsTestDataRhel7, err := ioutil.ReadFile(fileCollectVulnsTestDataRhel7)
	if err != nil {
		log.Fatal("error reading " + fileCollectVulnsTestDataRhel7)
	}
	ovalDocRhel7 := OvalV2Document{}
	err = xml.Unmarshal([]byte(xmlCollectVulnsTestDataRhel7), &ovalDocRhel7)
	if err != nil {
		// log error and continue
		log.Fatal(err)
	}
	fileCollectVulnsTestDataRhel8 := pwd + "/testdata/v2/collect-vulns-rhel8.xml"
	xmlCollectVulnsTestDataRhel8, err := ioutil.ReadFile(fileCollectVulnsTestDataRhel8)
	if err != nil {
		log.Fatal("error reading " + fileCollectVulnsTestDataRhel8)
	}
	var currentCollectedVulnerabilities = []database.VulnerabilityWithAffected{}
	var accumulatedVulnerabilities = []database.VulnerabilityWithAffected{}
	var pendingVulnNames = map[string]bool{}

	currentCollectedVulnerabilities = CollectVulnsForAdvisory(ParseAdvisory(ovalDocRhel7.DefinitionSet.Definitions[0], ovalDocRhel7), ovalDocRhel7)
	accumulatedVulnerabilities, pendingVulnNames = MergeVulnerabilities(currentCollectedVulnerabilities, accumulatedVulnerabilities, pendingVulnNames)

	// should find one vuln
	if (len(accumulatedVulnerabilities) != 1) {
		log.Fatal(fmt.Sprintf("error: wrong vulns count after first document parse (expected: 1; found: %d)", len(accumulatedVulnerabilities)))
	}
	// should find one vuln affected feature
	if (len(accumulatedVulnerabilities[0].Affected) != 1) {
		log.Fatal(fmt.Sprintf("error: wrong vaf count after first document parse (expected: 1; found: %d)", len(accumulatedVulnerabilities)))
	}

	ovalDocRhel8 := OvalV2Document{}
	err = xml.Unmarshal([]byte(xmlCollectVulnsTestDataRhel8), &ovalDocRhel8)
	if err != nil {
		// log error and continue
		log.Fatal(err)
	}
	currentCollectedVulnerabilities = CollectVulnsForAdvisory(ParseAdvisory(ovalDocRhel8.DefinitionSet.Definitions[0], ovalDocRhel8), ovalDocRhel8)
	accumulatedVulnerabilities, pendingVulnNames = MergeVulnerabilities(currentCollectedVulnerabilities, accumulatedVulnerabilities, pendingVulnNames)

	// should still find one vuln
	if (len(accumulatedVulnerabilities) != 1) {
		log.Fatal(fmt.Sprintf("error: wrong vulns count after second document parse (expected: 1; found: %d)", len(accumulatedVulnerabilities)))
	}
	// should find two vuln affected features
	if (len(accumulatedVulnerabilities[0].Affected) != 2) {
		log.Fatal(fmt.Sprintf("error: wrong vaf count after first document parse (expected: 2; found: %d)", len(accumulatedVulnerabilities)))
	}

	currentCollectedVulnerabilities = CollectVulnsForAdvisory(ParseAdvisory(ovalDocRhel7.DefinitionSet.Definitions[0], ovalDocRhel7), ovalDocRhel7)
	accumulatedVulnerabilities, pendingVulnNames = MergeVulnerabilities(currentCollectedVulnerabilities, accumulatedVulnerabilities, pendingVulnNames)

	// should still find one vuln
	if (len(accumulatedVulnerabilities) != 1) {
		log.Fatal(fmt.Sprintf("error: wrong vulns count after first document re-parse (expected: 1; found: %d)", len(accumulatedVulnerabilities)))
	}
	// should still find two vuln affected features
	if (len(accumulatedVulnerabilities[0].Affected) != 2) {
		log.Fatal(fmt.Sprintf("error: wrong vaf count after first document re-parse (expected: 2; found: %d)", len(accumulatedVulnerabilities)))
	}

}

type mockDatastore struct {
	database.MockDatastore

	keyValues map[string]string
}

type mockUpdaterSession struct {
	database.MockSession

	store      *mockDatastore
	copy       mockDatastore
	terminated bool
}

func copyDatastore(md *mockDatastore) mockDatastore {
	kv := map[string]string{
		DbManifestEntryKeyPrefix + "RHEL7/ansible-2.8.oval.xml.bz2": "b5a05dbe78f7d472f08bc4ad221d6018ce5e5ad32434f997fe395d54ebe21e65",
		DbManifestEntryKeyPrefix + "RHEL7/ansible-2.9.oval.xml.bz2": "109f1d47b6221333fce2d54052a7cdb9ef50bd29adf964c18f054f4aac62beaa",
		DbManifestEntryKeyPrefix + "RHEL8/ansible-2.8.oval.xml.bz2": "14a04f048080a246ef4e1d1c76e5beec12d16cbfd8013235f0ff2f88e4d78aed",
		DbManifestEntryKeyPrefix + "RHEL8/ansible-2.9.oval.xml.bz2": "6e6edbcaf0bb3bac108a796d7fb2d2c4f637f581d6c6d2bb8d0d0a87294d4460",
		DbLastAdvisoryDateKey: GetLastAdvisoryDate(),
	}
	for key, value := range md.keyValues {
		kv[key] = value
	}

	return mockDatastore{
		keyValues: kv,
	}
}

func newmockDatastore() *mockDatastore {
	errSessionDone := errors.New("Session Done")
	md := &mockDatastore{
		keyValues: make(map[string]string),
	}

	md.FctBegin = func() (database.Session, error) {
		session := &mockUpdaterSession{
			store:      md,
			copy:       copyDatastore(md),
			terminated: false,
		}

		session.FctCommit = func() error {
			if session.terminated {
				return errSessionDone
			}
			session.store.keyValues = session.copy.keyValues
			session.terminated = true
			return nil
		}

		session.FctRollback = func() error {
			if session.terminated {
				return errSessionDone
			}
			session.terminated = true
			session.copy = mockDatastore{}
			return nil
		}

		session.FctUpdateKeyValue = func(key, value string) error {
			session.copy.keyValues[key] = value
			return nil
		}

		session.FctFindKeyValue = func(key string) (string, bool, error) {
			s, b := session.copy.keyValues[key]
			return s, b, nil
		}

		//func FindVulnerabilitiesAndRollback(store Datastore, ids []database.VulnerabilityID) ([]database.NullableVulnerability, error) {
		session.FctFindVulnerabilities = func(ids []database.VulnerabilityID) ([]database.NullableVulnerability, error) {
			return []database.NullableVulnerability{}, nil
		}

		return session, nil
	}
	return md
}

