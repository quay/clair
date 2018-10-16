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

package nvd

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
)

type nvd struct {
	Entries []nvdEntry `json:"CVE_Items"`
}

type nvdEntry struct {
	CVE               nvdCVE    `json:"cve"`
	Impact            nvdImpact `json:"impact"`
	PublishedDateTime string    `json:"publishedDate"`
}

type nvdCVE struct {
	Metadata nvdCVEMetadata `json:"CVE_data_meta"`
}

type nvdCVEMetadata struct {
	CVEID string `json:"ID"`
}

type nvdImpact struct {
	BaseMetricV2 nvdBaseMetricV2 `json:"baseMetricV2"`
}

type nvdBaseMetricV2 struct {
	CVSSv2 nvdCVSSv2 `json:"cvssV2"`
}

type nvdCVSSv2 struct {
	Score            float64 `json:"baseScore"`
	AccessVector     string  `json:"accessVector"`
	AccessComplexity string  `json:"accessComplexity"`
	Authentication   string  `json:"authentication"`
	ConfImpact       string  `json:"confidentialityImpact"`
	IntegImpact      string  `json:"integrityImpact"`
	AvailImpact      string  `json:"availabilityImpact"`
}

var vectorValuesToLetters map[string]string

func init() {
	vectorValuesToLetters = make(map[string]string)
	vectorValuesToLetters["NETWORK"] = "N"
	vectorValuesToLetters["ADJACENT_NETWORK"] = "A"
	vectorValuesToLetters["LOCAL"] = "L"
	vectorValuesToLetters["HIGH"] = "H"
	vectorValuesToLetters["MEDIUM"] = "M"
	vectorValuesToLetters["LOW"] = "L"
	vectorValuesToLetters["NONE"] = "N"
	vectorValuesToLetters["SINGLE"] = "S"
	vectorValuesToLetters["MULTIPLE"] = "M"
	vectorValuesToLetters["PARTIAL"] = "P"
	vectorValuesToLetters["COMPLETE"] = "C"
}

func (n nvdEntry) Metadata() *NVDMetadata {
	metadata := &NVDMetadata{
		CVSSv2: NVDmetadataCVSSv2{
			PublishedDateTime: n.PublishedDateTime,
			Vectors:           n.Impact.BaseMetricV2.CVSSv2.String(),
			Score:             n.Impact.BaseMetricV2.CVSSv2.Score,
		},
	}

	if metadata.CVSSv2.Vectors == "" {
		return nil
	}

	return metadata
}

func (n nvdEntry) Name() string {
	return n.CVE.Metadata.CVEID
}

func (n nvdCVSSv2) String() string {
	var str string
	addVec(&str, "AV", n.AccessVector)
	addVec(&str, "AC", n.AccessComplexity)
	addVec(&str, "Au", n.Authentication)
	addVec(&str, "C", n.ConfImpact)
	addVec(&str, "I", n.IntegImpact)
	addVec(&str, "A", n.AvailImpact)
	str = strings.TrimSuffix(str, "/")
	return str
}

func addVec(str *string, vec, val string) {
	if val != "" {
		if let, ok := vectorValuesToLetters[val]; ok {
			*str = fmt.Sprintf("%s%s:%s/", *str, vec, let)
		} else {
			log.WithFields(log.Fields{"value": val, "vector": vec}).Warning("unknown value for CVSS vector")
		}
	}
}
