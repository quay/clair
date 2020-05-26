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
