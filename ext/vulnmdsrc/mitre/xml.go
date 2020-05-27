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

package mitre

import (
	"encoding/xml"
	log "github.com/sirupsen/logrus"
	"time"
)

const (
	simpleDateTime = "2006-01-02T15:04:05"
)

type mitreTime struct {
	time.Time
}

func (t *mitreTime) UnmarshalText(b []byte) error {
	tstamp, err := time.Parse(simpleDateTime, string(b))
	if err == nil {
		t.Time = tstamp
	}
	return err
}

// Start of source XML representation
type cvrfDoc struct {
	XMLName           xml.Name          `xml:"cvrfdoc"`
	DocumentTitle     string            `xml:"DocumentTitle"`
	DocumentType      string            `xml:"DocumentType"`
	DocumentPublisher documentPublisher `xml:"DocumentPublisher"`
	DocumentTracking  documentTracking  `xml:"DocumentTracking"`
	DocumentNotes     documentNotes     `xml:"DocumentNotes"`
	Vulnerability     []vulnerability   `xml:"Vulnerability"`
}

type documentPublisher struct {
	XMLName          xml.Name `xml:"DocumentPublisher"`
	ContactDetails   string   `xml:"ContactDetails"`
	IssuingAuthority string   `xml:"IssuingAuthority"`
}

type documentTracking struct {
	XMLName            xml.Name        `xml:"DocumentTracking"`
	Identification     identification  `xml:"Identification"`
	Status             string          `xml:"Status"`
	Version            string          `xml:"Version"`
	RevisionHistory    revisionHistory `xml:"RevisionHistory"`
	InitialReleaseDate mitreTime       `xml:"InitialReleaseDate"`
	CurrentReleaseDate mitreTime       `xml:"CurrentReleaseDate"`
	Generator          generator       `xml:"Generator"`
}

type documentNotes struct {
	XMLName xml.Name `xml:"DocumentNotes"`
	Note    []note   `xml:"Note"`
}

type revisionHistory struct {
	XMLName  xml.Name   `xml:"RevisionHistory"`
	Revision []revision `xml:"Revision"`
}

type vulnerability struct {
	XMLName    xml.Name   `xml:"Vulnerability"`
	Ordinal    uint64     `xml:"Ordinal,attr"`
	Title      string     `xml:"Title"`
	ID         vulnID     `xml:"ID"`
	Notes      vulnNote   `xml:"Notes"`
	CVE        string     `xml:"CVE"`
	References references `xml:"References"`
}

type generator struct {
	XMLName xml.Name `xml:"Generator"`
	Engine  []engine `xml:"Engine"`
}

type identification struct {
	XMLName xml.Name `xml:"Identification"`
	ID      []string `xml:"ID"`
}

type references struct {
	XMLName   xml.Name    `xml:"References"`
	Reference []reference `xml:"Reference"`
}

type revision struct {
	XMLName     xml.Name  `xml:"Revision"`
	Number      uint      `xml:"Number"`
	Date        mitreTime `xml:"Date"`
	Description string    `xml:"Description"`
}

type engine struct {
	XMLName xml.Name `xml:"Engine"`
	Engine  string   `xml:",chardata"`
}

type vulnID struct {
	XMLName    xml.Name `xml:"ID"`
	SystemName string   `xml:"SystemName,attr"`
}

type vulnNote struct {
	XMLName xml.Name `xml:"Notes"`
	Note    []note   `xml:"Note"`
}

type note struct {
	XMLName  xml.Name `xml:"Note"`
	Type     string   `xml:"Type,attr"`
	Ordinal  uint64   `xml:"Ordinal,attr"`
	Title    string   `xml:"Title,attr"`
	Audience string   `xml:"Audience,attr"` // this is only used for the DocumentNotes but does no harm in the notes for vulnerabilities
	Note     string   `xml:",chardata"`
}

type reference struct {
	XMLName     xml.Name `xml:"Reference"`
	URL         string   `xml:"URL"`
	Description string   `xml:"Description"`
}

func (v vulnerability) Metadata() *MitreMetadata {
	if v.References.Reference == nil {
		return nil
	}
	return &MitreMetadata{
		ReferenceURLs: v.StringArray(),
	}
}

// End of source XML representation

func (v vulnerability) Name() string {
	return v.CVE
}

func (v vulnerability) StringArray() []string {
	urls := make([]string, len(v.References.Reference))
	for idx, r := range v.References.Reference {
		if r.URL != "" {
			urls[idx] = r.URL
		} else {
			log.WithFields(log.Fields{"description": r.Description}).Warning("no reference URL provided")
		}
	}
	return urls
}
