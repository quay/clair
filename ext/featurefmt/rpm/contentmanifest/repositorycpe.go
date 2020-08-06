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

package contentmanifest

import (
	"github.com/quay/clair/v3/pkg/envutil"
	log "github.com/sirupsen/logrus"
)

// RepoCPEUpdater provides interface for providing a mapping
// between repositories and CPEs
type RepoCPEUpdater interface {
	Update() error
	Get([]string) ([]string, error)
}

// RepoCPEMapping struct handles translation of repositories to CPEs
type RepoCPEMapping struct {
	RepoCPEUpdater
}

var (
	// MappingFileURL is URL to a mapping file with default value
	MappingFileURL = envutil.GetEnv(
		"REPO_CPE_MAPPING_URL",
		"https://www.redhat.com/security/data/metrics/repository-to-cpe.json",
	)
)

// RepositoryToCPE translates repositories into CPEs
func (mapping *RepoCPEMapping) RepositoryToCPE(repositories []string) ([]string, error) {
	log.WithField("repositories", repositories).Debug("Translating repositories into CPEs")
	if len(repositories) == 0 {
		return []string{}, nil
	}
	err := mapping.Update()
	if err != nil {
		return []string{}, err
	}
	return mapping.Get(repositories)
}
