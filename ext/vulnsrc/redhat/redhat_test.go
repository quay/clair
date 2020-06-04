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
		{"1", args{OvalV2Criterion{Comment:"softhsm-devel is earlier than 0:2.4.0-2.module+el8.1.0+4098+f286395e"}}, true},
		{"2", args{OvalV2Criterion{Comment:"Red Hat Enterprise Linux must be installed"}}, false},
		{"3", args{OvalV2Criterion{Comment:"Module idm:DL1 is enabled"}}, false},
		{"4", args{OvalV2Criterion{Comment:"softhsm-devel is signed with Red Hat redhatrelease2 key"}}, false},
		{"5", args{OvalV2Criterion{Comment:""}}, false},
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
	xmlFilePath := pwd + "/testdata/v2/ansible-2.8.oval.xml"
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
		// cpe:/a:redhat:ansible_engine:2.8::el8
		{
			"1",
			args{ovalDoc.DefinitionSet.Definitions[0].Metadata.Advisory.AffectedCpeList},
			[]string{
				"cpe:/a:redhat:ansible_engine:2.8",
				"cpe:/a:redhat:ansible_engine:2.8::el8",
				// []CpeName{
				// 	{Part: "a", Vendor: "redhat", Product: "ansible_engine", Version: "2.8", Update: "", Edition: "el8", Language: ""},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCpeNamesFromAffectedCpeList(tt.args.affectedCpeList)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCpeNamesFromAffectedCpeList() error = %v, wantErr %v", err, tt.wantErr)
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
		{"None", args{"None"},false},
		{"Low", args{"Low"},true},
		{"Moderate", args{"Moderate"},true},
		{"Important", args{"Important"},true},
		{"Critical", args{"Critical"},true},
		{"Unknown", args{"Unknown"},true},
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
		{"None", args{"None"},database.NegligibleSeverity},
		{"Low", args{"Low"},database.LowSeverity},
		{"Moderate", args{"Moderate"},database.MediumSeverity},
		{"Important", args{"Important"},database.HighSeverity},
		{"Critical", args{"Critical"},database.CriticalSeverity},
		{"Unknown", args{"Unknown"},database.UnknownSeverity},
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

