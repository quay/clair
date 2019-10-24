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

// Package redhatrpm implements a featurefmt.Lister for Red Hat's rpm packages.
package redhatrpm

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

var lbCertPath = os.Getenv("LB_CERT_PATH")
var lbURL = os.Getenv("LB_URL")

type LBContainerImage struct {
	Status     string           `json:"status"`
	MatchCount int              `json:"matchCount"`
	Images     []ContainerImage `json:"processed"`
}

type ContainerImage struct {
	Repositories []struct {
		Registry   string `json:"registry"`
		Published  bool   `json:"published"`
		Repository string `json:"repository"`
	} `json:"repositories"`
	Architecture string   `json:"architecture"`
	CPE          []string `json:"cpe_ids"`
	ParsedData   struct {
		Architecture string `json:"architecture"`
		Labels       []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"labels"`
	} `json:"parsed_data"`
}

type LBCpeNamespaceFetcher struct{}

// GetCPEs fetches CPE information for given build from Lightblue database
func (fetcher *LBCpeNamespaceFetcher) GetCPEs(nvr, arch string) []string {
	clientCert, err := tls.LoadX509KeyPair(lbCertPath, lbCertPath)
	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{clientCert},
	}

	transport := http.Transport{
		TLSClientConfig: &tlsConfig,
	}

	client := http.Client{
		Transport: &transport,
	}

	resp, err := client.Get(lbURL + "/rest/data/find/containerImage/?Q=brew.build:" + nvr)
	if err != nil {
		return []string{}
	}

	var ci LBContainerImage
	err = json.NewDecoder(resp.Body).Decode(&ci)
	if err != nil {
		fmt.Println(err)
	}
	if len(ci.Images) == 0 {
		return []string{}
	}
	var images []ContainerImage
	for _, image := range ci.Images {
		for _, label := range image.ParsedData.Labels {
			if label.Name == "architecture" {
				if label.Value == arch {
					images = append(images, image)
				}
			}
		}
	}
	CPEs := images[0].CPE
	// preffer published image
	for _, image := range images {
		if len(image.Repositories) > 0 {
			if image.Repositories[0].Published {
				CPEs = image.CPE
				break
			}
		}
	}
	return CPEs
}
