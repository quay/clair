package registry

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"

	"github.com/docker/docker/reference"
	"github.com/docker/engine-api/types"
	registrytypes "github.com/docker/engine-api/types/registry"
)

// Service is a registry service. It tracks configuration data such as a list
// of mirrors.
type Service struct {
	Config *registrytypes.ServiceConfig
}

// NewService returns a new instance of Service ready to be
// installed into an engine.
func NewService(options *Options) *Service {
	return &Service{
		Config: NewServiceConfig(options),
	}
}

// Auth contacts the public registry with the provided credentials,
// and returns OK if authentication was successful.
// It can be used to verify the validity of a client's credentials.
func (s *Service) Auth(authConfig *types.AuthConfig, userAgent string) (string, error) {
	addr := authConfig.ServerAddress
	if addr == "" {
		// Use the official registry address if not specified.
		addr = IndexServer
	}
	index, err := s.ResolveIndex(addr)
	if err != nil {
		return "", err
	}

	endpointVersion := APIVersion(APIVersionUnknown)
	if V2Only {
		// Override the endpoint to only attempt a v2 ping
		endpointVersion = APIVersion2
	}

	endpoint, err := NewEndpoint(index, userAgent, nil, endpointVersion)
	if err != nil {
		return "", err
	}
	authConfig.ServerAddress = endpoint.String()
	return Login(authConfig, endpoint)
}

// splitReposSearchTerm breaks a search term into an index name and remote name
func splitReposSearchTerm(reposName string) (string, string) {
	nameParts := strings.SplitN(reposName, "/", 2)
	var indexName, remoteName string
	if len(nameParts) == 1 || (!strings.Contains(nameParts[0], ".") &&
		!strings.Contains(nameParts[0], ":") && nameParts[0] != "localhost") {
		// This is a Docker Index repos (ex: samalba/hipache or ubuntu)
		// 'docker.io'
		indexName = IndexName
		remoteName = reposName
	} else {
		indexName = nameParts[0]
		remoteName = nameParts[1]
	}
	return indexName, remoteName
}

// Search queries the public registry for images matching the specified
// search terms, and returns the results.
func (s *Service) Search(term string, authConfig *types.AuthConfig, userAgent string, headers map[string][]string) (*registrytypes.SearchResults, error) {
	if err := validateNoSchema(term); err != nil {
		return nil, err
	}

	indexName, remoteName := splitReposSearchTerm(term)

	index, err := newIndexInfo(s.Config, indexName)
	if err != nil {
		return nil, err
	}

	// *TODO: Search multiple indexes.
	endpoint, err := NewEndpoint(index, userAgent, http.Header(headers), APIVersionUnknown)
	if err != nil {
		return nil, err
	}

	r, err := NewSession(endpoint.client, authConfig, endpoint)
	if err != nil {
		return nil, err
	}

	if index.Official {
		localName := remoteName
		if strings.HasPrefix(localName, "library/") {
			// If pull "library/foo", it's stored locally under "foo"
			localName = strings.SplitN(localName, "/", 2)[1]
		}

		return r.SearchRepositories(localName)
	}
	return r.SearchRepositories(remoteName)
}

// ResolveRepository splits a repository name into its components
// and configuration of the associated registry.
func (s *Service) ResolveRepository(name reference.Named) (*RepositoryInfo, error) {
	return newRepositoryInfo(s.Config, name)
}

// ResolveIndex takes indexName and returns index info
func (s *Service) ResolveIndex(name string) (*registrytypes.IndexInfo, error) {
	return newIndexInfo(s.Config, name)
}

// APIEndpoint represents a remote API endpoint
type APIEndpoint struct {
	Mirror       bool
	URL          *url.URL
	Version      APIVersion
	Official     bool
	TrimHostname bool
	TLSConfig    *tls.Config
}

// ToV1Endpoint returns a V1 API endpoint based on the APIEndpoint
func (e APIEndpoint) ToV1Endpoint(userAgent string, metaHeaders http.Header) (*Endpoint, error) {
	return newEndpoint(*e.URL, e.TLSConfig, userAgent, metaHeaders)
}

// TLSConfig constructs a client TLS configuration based on server defaults
func (s *Service) TLSConfig(hostname string) (*tls.Config, error) {
	return newTLSConfig(hostname, isSecureIndex(s.Config, hostname))
}

func (s *Service) tlsConfigForMirror(mirrorURL *url.URL) (*tls.Config, error) {
	return s.TLSConfig(mirrorURL.Host)
}

// LookupPullEndpoints creates an list of endpoints to try to pull from, in order of preference.
// It gives preference to v2 endpoints over v1, mirrors over the actual
// registry, and HTTPS over plain HTTP.
func (s *Service) LookupPullEndpoints(repoName reference.Named) (endpoints []APIEndpoint, err error) {
	return s.lookupEndpoints(repoName)
}

// LookupPushEndpoints creates an list of endpoints to try to push to, in order of preference.
// It gives preference to v2 endpoints over v1, and HTTPS over plain HTTP.
// Mirrors are not included.
func (s *Service) LookupPushEndpoints(repoName reference.Named) (endpoints []APIEndpoint, err error) {
	allEndpoints, err := s.lookupEndpoints(repoName)
	if err == nil {
		for _, endpoint := range allEndpoints {
			if !endpoint.Mirror {
				endpoints = append(endpoints, endpoint)
			}
		}
	}
	return endpoints, err
}

func (s *Service) lookupEndpoints(repoName reference.Named) (endpoints []APIEndpoint, err error) {
	endpoints, err = s.lookupV2Endpoints(repoName)
	if err != nil {
		return nil, err
	}

	if V2Only {
		return endpoints, nil
	}

	legacyEndpoints, err := s.lookupV1Endpoints(repoName)
	if err != nil {
		return nil, err
	}
	endpoints = append(endpoints, legacyEndpoints...)

	return endpoints, nil
}
