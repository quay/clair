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
	Entries []nvdEntry `xml:"entry"`
}

type nvdEntry struct {
	Name string  `xml:"http://scap.nist.gov/schema/vulnerability/0.4 cve-id"`
	CVSS nvdCVSS `xml:"http://scap.nist.gov/schema/vulnerability/0.4 cvss"`
}

type nvdCVSS struct {
	BaseMetrics nvdCVSSBaseMetrics `xml:"http://scap.nist.gov/schema/cvss-v2/0.2 base_metrics"`
}

type nvdCVSSBaseMetrics struct {
	Score            float64 `xml:"score"`
	AccessVector     string  `xml:"access-vector"`
	AccessComplexity string  `xml:"access-complexity"`
	Authentication   string  `xml:"authentication"`
	ConfImpact       string  `xml:"confidentiality-impact"`
	IntegImpact      string  `xml:"integrity-impact"`
	AvailImpact      string  `xml:"avaibility-impact"`
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
	vectorValuesToLetters["SINGLE_INSTANCE"] = "S"
	vectorValuesToLetters["MULTIPLE_INSTANCES"] = "M"
	vectorValuesToLetters["PARTIAL"] = "P"
	vectorValuesToLetters["COMPLETE"] = "C"
}

func (n nvdEntry) Metadata() *NVDMetadata {
	metadata := &NVDMetadata{
		CVSSv2: NVDmetadataCVSSv2{
			Vectors: n.CVSS.BaseMetrics.String(),
			Score:   n.CVSS.BaseMetrics.Score,
		},
	}

	if metadata.CVSSv2.Vectors == "" {
		return nil
	}
	return metadata
}

func (n nvdCVSSBaseMetrics) String() string {
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
			log.WithFields(log.Fields{"value": val, "vector": vec}).Warning("unknown value for CVSSv2 vector")
		}
	}
}
