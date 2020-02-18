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

// Package errata provides basic client for Errata Tool API
package errata

import (
	"fmt"
	"net/http"
	"time"

	"encoding/json"

	log "github.com/sirupsen/logrus"

	"github.com/quay/clair/v3/pkg/commonerr"
	"github.com/quay/clair/v3/pkg/envutil"
	"github.com/quay/clair/v3/pkg/httputil"
	"gopkg.in/jcmturner/gokrb5.v7/client"
	"gopkg.in/jcmturner/gokrb5.v7/config"
	"gopkg.in/jcmturner/gokrb5.v7/keytab"
	"gopkg.in/jcmturner/gokrb5.v7/spnego"
)

type Variant struct {
	Attributes struct {
		Name    string `json:"name"`
		Cpe     string `json:"cpe"`
		Enabled bool   `json:"enabled"`
	} `json:"attributes"`
}
type VariantResponse struct {
	Data []Variant `json:"data"`
}

// Errata client API structure

type ErrataInterface interface {
	NewClient() (*spnego.Client, error)
	GetAllVariants() ([]Variant, error)
	VariantToCPEMapping(variants []Variant) map[string]string
	GetAdvisoryBuildsVariants(advisoryID string) (map[string][]string, error)
}

type Errata struct {
	URL string
}

var krbConfPath = envutil.GetEnv("KRB_CONF", "/etc/krb5.conf")
var krbUsername = envutil.GetEnv("KRB_USERNAME", "")
var krbRealm = envutil.GetEnv("KRB_REALM", "")
var krbKeytabPath = envutil.GetEnv("KRB_KEYTAB_PATH", "")

// NewClient - creates new http Errata Tool client with krb auth
func (et *Errata) NewClient() (*spnego.Client, error) {
	cfg, err := config.Load(krbConfPath)
	if err != nil {
		return nil, err
	}

	kt, err := keytab.Load(krbKeytabPath)
	if err != nil {
		return nil, err
	}
	cl := client.NewClientWithKeytab(krbUsername, krbRealm, kt, cfg)
	cl.Login()
	httpClient := http.Client{Timeout: time.Minute}
	client := spnego.NewClient(cl, &httpClient, "")

	return client, nil
}

// GetAllVariants fetches information about all varianst availabe in Errata Tool
func (et *Errata) GetAllVariants() ([]Variant, error) {
	pageNumber := 1
	var variants []Variant
	cl, err := et.NewClient()
	if err != nil {
		return variants, err
	}
	for {
		url := fmt.Sprintf("%s/api/v1/variants?page[number]=%d&page[size]=200", et.URL, pageNumber)
		request, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := cl.Do(request)
		if err != nil {
			return nil, err
		}
		if !httputil.Status2xx(resp) {
			log.WithField("StatusCode", resp.StatusCode).Error("Failed to fetch ET variants")
			return nil, commonerr.ErrCouldNotDownload
		}
		variantResp := new(VariantResponse)
		err = json.NewDecoder(resp.Body).Decode(&variantResp)
		if err != nil {
			return nil, err
		}
		resp.Body.Close()
		if len(variantResp.Data) == 0 {
			// end of paginated response
			break
		}
		pageNumber++
		for _, item := range variantResp.Data {
			variants = append(variants, item)
		}
	}
	return variants, nil
}

// VariantToCPEMapping creates map with variants as keys and CPEs as value
func (et *Errata) VariantToCPEMapping(variants []Variant) map[string]string {
	mapping := make(map[string]string)
	for _, variant := range variants {
		if variant.Attributes.Cpe == "" {
			// Some variants has empty CPE string
			continue
		}
		mapping[variant.Attributes.Name] = variant.Attributes.Cpe
	}
	return mapping
}

// GetAdvisoryBuildsVariants get advisory information about packages and its variants
func (et *Errata) GetAdvisoryBuildsVariants(advisoryID string) (map[string][]string, error) {
	pkgToVariant := make(map[string][]string)
	cl, err := et.NewClient()
	if err != nil {
		return pkgToVariant, err
	}
	url := fmt.Sprintf("%s/advisory/%s/builds.json", et.URL, advisoryID)
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return pkgToVariant, err
	}
	resp, err := cl.Do(request)
	if err != nil {
		return pkgToVariant, err
	}
	if !httputil.Status2xx(resp) {
		log.WithField("StatusCode", resp.StatusCode).Error("Failed to fetch advisory details")
		return nil, commonerr.ErrCouldNotDownload
	}
	// This is awful, but ET API response is made of dynamic keys in json
	type AdvisoryBuilds map[string][]map[string]map[string]map[string][]string
	advisoryBuildsResp := new(AdvisoryBuilds)
	err = json.NewDecoder(resp.Body).Decode(&advisoryBuildsResp)
	if err != nil {
		return pkgToVariant, err
	}
	resp.Body.Close()
	for _, productVersionObj := range *advisoryBuildsResp {
		for _, item := range productVersionObj {
			for _, buildObj := range item {
				for variant, variantObj := range buildObj {
					for _, archObj := range variantObj {
						for _, pkg := range archObj {
							pkgToVariant[pkg] = append(pkgToVariant[pkg], variant)

						}
					}
				}
			}
		}
	}
	return pkgToVariant, nil
}
