// Copyright 2017 The Grafeas Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package testutil

import (
	"fmt"
	"log"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	pb "github.com/grafeas/grafeas/v1alpha1/proto"
	opspb "google.golang.org/genproto/googleapis/longrunning"
)

func Occurrence(pID, noteName string) *pb.Occurrence {
	return &pb.Occurrence{
		Name:        fmt.Sprintf("projects/%s/occurrences/134", pID),
		ResourceUrl: "gcr.io/foo/bar",
		NoteName:    noteName,
		Kind:        pb.Note_PACKAGE_VULNERABILITY,
		Details: &pb.Occurrence_VulnerabilityDetails{
			VulnerabilityDetails: &pb.VulnerabilityType_VulnerabilityDetails{
				Severity:  pb.VulnerabilityType_HIGH,
				CvssScore: 7.5,
				PackageIssue: []*pb.VulnerabilityType_PackageIssue{
					&pb.VulnerabilityType_PackageIssue{
						SeverityName: "HIGH",
						AffectedLocation: &pb.VulnerabilityType_VulnerabilityLocation{
							CpeUri:  "cpe:/o:debian:debian_linux:8",
							Package: "icu",
							Version: &pb.VulnerabilityType_Version{
								Name:     "52.1",
								Revision: "8+deb8u3",
							},
						},
						FixedLocation: &pb.VulnerabilityType_VulnerabilityLocation{
							CpeUri:  "cpe:/o:debian:debian_linux:8",
							Package: "icu",
							Version: &pb.VulnerabilityType_Version{
								Name:     "52.1",
								Revision: "8+deb8u4",
							},
						},
					},
				},
			},
		},
	}
}

func Note(pID string) *pb.Note {
	return &pb.Note{
		Name:             fmt.Sprintf("projects/%s/notes/CVE-1999-0710", pID),
		ShortDescription: "CVE-2014-9911",
		LongDescription:  "NIST vectors: AV:N/AC:L/Au:N/C:P/I:P",
		Kind:             pb.Note_PACKAGE_VULNERABILITY,
		NoteType: &pb.Note_VulnerabilityType{
			&pb.VulnerabilityType{
				CvssScore: 7.5,
				Severity:  pb.VulnerabilityType_HIGH,
				Details: []*pb.VulnerabilityType_Detail{
					&pb.VulnerabilityType_Detail{
						CpeUri:  "cpe:/o:debian:debian_linux:7",
						Package: "icu",
						Description: "Stack-based buffer overflow in the ures_getByKeyWithFallback function in " +
							"common/uresbund.cpp in International Components for Unicode (ICU) before 54.1 for C/C++ allows " +
							"remote attackers to cause a denial of service or possibly have unspecified other impact via a crafted uloc_getDisplayName call.",
						MinAffectedVersion: &pb.VulnerabilityType_Version{
							Kind: pb.VulnerabilityType_Version_MINIMUM,
						},
						SeverityName: "HIGH",

						FixedLocation: &pb.VulnerabilityType_VulnerabilityLocation{
							CpeUri:  "cpe:/o:debian:debian_linux:7",
							Package: "icu",
							Version: &pb.VulnerabilityType_Version{
								Name:     "4.8.1.1",
								Revision: "12+deb7u6",
							},
						},
					},
					&pb.VulnerabilityType_Detail{
						CpeUri:  "cpe:/o:debian:debian_linux:8",
						Package: "icu",
						Description: "Stack-based buffer overflow in the ures_getByKeyWithFallback function in " +
							"common/uresbund.cpp in International Components for Unicode (ICU) before 54.1 for C/C++ allows " +
							"remote attackers to cause a denial of service or possibly have unspecified other impact via a crafted uloc_getDisplayName call.",
						MinAffectedVersion: &pb.VulnerabilityType_Version{
							Kind: pb.VulnerabilityType_Version_MINIMUM,
						},
						SeverityName: "HIGH",

						FixedLocation: &pb.VulnerabilityType_VulnerabilityLocation{
							CpeUri:  "cpe:/o:debian:debian_linux:8",
							Package: "icu",
							Version: &pb.VulnerabilityType_Version{
								Name:     "52.1",
								Revision: "8+deb8u4",
							},
						},
					},
					&pb.VulnerabilityType_Detail{
						CpeUri:  "cpe:/o:debian:debian_linux:9",
						Package: "icu",
						Description: "Stack-based buffer overflow in the ures_getByKeyWithFallback function in " +
							"common/uresbund.cpp in International Components for Unicode (ICU) before 54.1 for C/C++ allows " +
							"remote attackers to cause a denial of service or possibly have unspecified other impact via a crafted uloc_getDisplayName call.",
						MinAffectedVersion: &pb.VulnerabilityType_Version{
							Kind: pb.VulnerabilityType_Version_MINIMUM,
						},
						SeverityName: "HIGH",

						FixedLocation: &pb.VulnerabilityType_VulnerabilityLocation{
							CpeUri:  "cpe:/o:debian:debian_linux:9",
							Package: "icu",
							Version: &pb.VulnerabilityType_Version{
								Name:     "55.1",
								Revision: "3",
							},
						},
					},
					&pb.VulnerabilityType_Detail{
						CpeUri:  "cpe:/o:canonical:ubuntu_linux:14.04",
						Package: "andriod",
						Description: "Stack-based buffer overflow in the ures_getByKeyWithFallback function in " +
							"common/uresbund.cpp in International Components for Unicode (ICU) before 54.1 for C/C++ allows " +
							"remote attackers to cause a denial of service or possibly have unspecified other impact via a crafted uloc_getDisplayName call.",
						MinAffectedVersion: &pb.VulnerabilityType_Version{
							Kind: pb.VulnerabilityType_Version_MINIMUM,
						},
						SeverityName: "MEDIUM",

						FixedLocation: &pb.VulnerabilityType_VulnerabilityLocation{
							CpeUri:  "cpe:/o:canonical:ubuntu_linux:14.04",
							Package: "andriod",
							Version: &pb.VulnerabilityType_Version{
								Kind: pb.VulnerabilityType_Version_MAXIMUM,
							},
						},
					},
				},
			},
		},
		RelatedUrl: []*pb.Note_RelatedUrl{
			&pb.Note_RelatedUrl{
				Url:   "https://security-tracker.debian.org/tracker/CVE-2014-9911",
				Label: "More Info",
			},
			&pb.Note_RelatedUrl{
				Url:   "http://people.ubuntu.com/~ubuntu-security/cve/CVE-2014-9911",
				Label: "More Info",
			},
		},
	}
}

func Operation(pID string) *opspb.Operation {
	md := &pb.OperationMetadata{CreateTime: ptypes.TimestampNow()}
	bytes, err := proto.Marshal(md)
	if err != nil {
		log.Printf("Error parsing bytes: %v", err)
		return nil
	}
	return &opspb.Operation{
		Name:     fmt.Sprintf("projects/%s/operations/foo", pID),
		Metadata: &any.Any{Value: bytes},
		Done:     false,
	}
}
