// Copyright 2020 clair authors
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

// Package rpm implements a featurefmt.Lister for rpm packages.
package rpm

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/quay/clair/v3/pkg/envutil"
	"github.com/quay/clair/v3/pkg/httputil"
)

var apiURL = envutil.GetEnv("CONTINER_API_URL", "https://catalog.redhat.com/api/containers")
var apiCertPath = envutil.GetEnv("CONTINER_API_CERT_PATH", "")

type ContainerImages struct {
	Images []ContainerImage `json:"data"`
}

type ContainerImage struct {
	CPE        []string `json:"cpe_ids"`
	ParsedData struct {
		Architecture string `json:"architecture"`
		Labels       []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"labels"`
	} `json:"parsed_data"`
}

type ContainerApiCpeNamespaceFetcher struct{}

// GetCPEs fetches CPE information for given build from Lightblue database
func (fetcher *ContainerApiCpeNamespaceFetcher) GetCPEs(nvr, arch string) (cpes []string, err error) {
	transport := http.Transport{}
	if apiCertPath != "" {

		clientCert, err := tls.LoadX509KeyPair(apiCertPath, apiCertPath)
		if err != nil {
			return []string{}, err
		}
		tlsConfig := tls.Config{
			Certificates: []tls.Certificate{clientCert},
		}

		transport = http.Transport{
			TLSClientConfig: &tlsConfig,
		}
	}

	client := http.Client{
		Transport: &transport,
	}
	url := apiURL + "/v1/images/nvr/" + nvr
	resp, err := client.Get(url)
	if err != nil {
		return
	}
	if !httputil.Status2xx(resp) {
		err = fmt.Errorf("Got non 200 code from: '%s'", url)
		return
	}

	var ci ContainerImages
	err = json.NewDecoder(resp.Body).Decode(&ci)
	if err != nil {
		fmt.Errorf("Unexpected format: '%s'", url)
	}
	for _, image := range ci.Images {
		for _, label := range image.ParsedData.Labels {
			if label.Name == "architecture" {
				if label.Value == arch {
					return image.CPE, nil
				}
			}
		}
	}
	return
}
