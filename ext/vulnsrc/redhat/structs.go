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

// Package redhat - structs.go provides structs used by the redhat package
//   (keeping separate for organization/clarity)
package redhat

import (
	"encoding/xml"
)

type updater struct{}

// ManifestEntry - comma-delimited manifest entry line from PULP_MANIFEST
// format:
//  [rhel version]/[platform bz2 file],[file sha256sum],[file bytes]
// e.g.:
//  RHEL8/ansible-2.8.oval.xml.bz2,14a04f048080a246ef4e1d1c76e5beec12d16cbfd8013235f0ff2f88e4d78aed,3755
type ManifestEntry struct {
	BzipPath  string // RHEL8/ansible-2.8.oval.xml.bz2
	Signature string // 14a04f048080a246ef4e1d1c76e5beec12d16cbfd8013235f0ff2f88e4d78aed
	Size      int    // 3755
}

// OvalV2Document - represents an uncompressed ovalV2 bzip document linked from PULP_MANIFEST
type OvalV2Document struct {
	XMLName       xml.Name                  `xml:"oval_definitions"`
	DefinitionSet OvalV2AdvisoryDefinitions `xml:"definitions"`
	TestSet       OvalV2Tests               `xml:"tests"`
	ObjectSet     OvalV2Objects             `xml:"objects"`
	StateSet      OvalV2States              `xml:"states"`
}

// OvalV2AdvisoryDefinitions - OvalV2Document.definition array
type OvalV2AdvisoryDefinitions struct {
	Definitions []OvalV2AdvisoryDefinition `xml:"definition"`
}

// OvalV2AdvisoryDefinition - single definition from ovalV2 document
type OvalV2AdvisoryDefinition struct {
	Class    string         `xml:"class,attr"`
	ID       string         `xml:"id,attr"`
	Version  string         `xml:"version,attr"`
	Metadata OvalV2Metadata `xml:"metadata"`
	Criteria OvalV2Criteria `xml:"criteria"`
}

// OvalV2Metadata - advisory metadata
type OvalV2Metadata struct {
	Title       string            `xml:"title"`
	Reference   []OvalV2Reference `xml:"reference"`
	Description string            `xml:"description"`
	Advisory    OvalV2Advisory    `xml:"advisory"`
}

// OvalV2Reference - advisory reference
type OvalV2Reference struct {
	RefID  string `xml:"ref_id"`
	RefURL string `xml:"ref_url"`
	Source string `xml:"source"`
}

// OvalV2Advisory - advisory data
type OvalV2Advisory struct {
	Issued          OvalV2AdvisoryIssued  `xml:"issued"`
	Updated         OvalV2AdvisoryUpdated `xml:"updated"`
	Severity        string                `xml:"severity"`
	CveList         []OvalV2CveData       `xml:"cve"`
	AffectedCpeList OvalV2Cpe             `xml:"affected_cpe_list"`
}

// OvalV2AdvisoryIssued - date advisory was issued (YYYY-MM-DD)
type OvalV2AdvisoryIssued struct {
	Date string `xml:"date,attr"`
}

// OvalV2AdvisoryUpdated - date advisory was issued (YYYY-MM-DD)
type OvalV2AdvisoryUpdated struct {
	Date string `xml:"date,attr"`
}

// OvalV2CveData - advisory cve data
type OvalV2CveData struct {
	XMLName xml.Name `xml:"cve"`
	Cvss3   string   `xml:"cvss3,attr"`
	Cwe     string   `xml:"cwe,attr"`
	Href    string   `xml:"href,attr"`
	Public  string   `xml:"public,attr"`
	Value   string   `xml:",chardata"`
}

// OvalV2Cpe - advisory affected cpes
type OvalV2Cpe struct {
	Cpe []string `xml:"cpe"`
}

// CpeName - cpe name components
type CpeName struct {
	Part     string
	Vendor   string
	Product  string
	Version  string
	Update   string
	Edition  string
	Language string
}

// OvalV2Criteria - advisory-related criteria set
type OvalV2Criteria struct {
	Criterion []OvalV2Criterion `xml:"criterion"`
	Criteria  []OvalV2Criteria  `xml:"criteria"`
}

// OvalV2Criterion - advisory-related criteria item
type OvalV2Criterion struct {
	XMLName xml.Name `xml:"criterion"`
	Comment string   `xml:"comment,attr"`
	TestRef string   `xml:"test_ref,attr"`
}

// OvalV2Tests - oval tests
type OvalV2Tests struct {
	XMLName xml.Name            `xml:"tests"`
	Tests   []OvalV2RpmInfoTest `xml:"rpminfo_test"`
}

// OvalV2RpmInfoTest - oval tests.rpminfo_test
type OvalV2RpmInfoTest struct {
	Comment   string               `xml:"comment,attr"`
	ID        string               `xml:"id,attr"`
	ObjectRef RpmInfoTestObjectRef `xml:"object"`
	StateRef  RpmInfoTestStateRef  `xml:"state"`
}

// RpmInfoTestObjectRef - oval reference to test info
type RpmInfoTestObjectRef struct {
	Ref string `xml:"object_ref,attr"`
}

// RpmInfoTestStateRef - oval reference to state info
type RpmInfoTestStateRef struct {
	Ref string `xml:"state_ref,attr"`
}

// OvalV2Objects - ovalV2 objects set
type OvalV2Objects struct {
	XMLName xml.Name              `xml:"objects"`
	Objects []OvalV2RpmInfoObject `xml:"rpminfo_object"`
}

// OvalV2RpmInfoObject - rpm info
type OvalV2RpmInfoObject struct {
	ID      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
	Name    string `xml:"name"`
}

// OvalV2States - state info
type OvalV2States struct {
	XMLName xml.Name             `xml:"states"`
	States  []OvalV2RpmInfoState `xml:"rpminfo_state"`
}

// OvalV2RpmInfoState - state info
type OvalV2RpmInfoState struct {
	ID      string            `xml:"id,attr"`
	Version string            `xml:"version,attr"`
	Arch    RpmInfoStateChild `xml:"arch"`
	Evr     RpmInfoStateChild `xml:"evr"`
}

// RpmInfoStateChild - arch and evr state info
type RpmInfoStateChild struct {
	DataType  string `xml:"datatype,attr"`
	Operation string `xml:"operation,attr"`
	Value     string `xml:",chardata"`
}

// OvalV2DefinitionNamespaces - module and cpe namespace info
type OvalV2DefinitionNamespaces struct {
	ModuleNamespaces []string
	CpeNamespaces    []string
}

// RpmNvra - rpm nvra info
type RpmNvra struct {
	Name    string
	Version string
	Release string
	Arch    string
}

// ParsedAdvisory - parsed advisory info, including relevant criteria and package references
type ParsedAdvisory struct {
	Class       string
	ID          string
	Version     string
	Metadata    OvalV2Metadata
	Criteria    OvalV2Criteria
	PackageList []ParsedRmpNvra
}

// ParsedRmpNvra - parsed rpm nvra info
type ParsedRmpNvra struct {
	Name string
	Evr  string
	Arch string
}
