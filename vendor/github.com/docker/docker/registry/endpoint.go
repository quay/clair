package registry

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/docker/distribution/registry/api/v2"
	"github.com/docker/distribution/registry/client/transport"
	registrytypes "github.com/docker/engine-api/types/registry"
)

// for mocking in unit tests
var lookupIP = net.LookupIP

// scans string for api version in the URL path. returns the trimmed address, if version found, string and API version.
func scanForAPIVersion(address string) (string, APIVersion) {
	var (
		chunks        []string
		apiVersionStr string
	)

	if strings.HasSuffix(address, "/") {
		address = address[:len(address)-1]
	}

	chunks = strings.Split(address, "/")
	apiVersionStr = chunks[len(chunks)-1]

	for k, v := range apiVersions {
		if apiVersionStr == v {
			address = strings.Join(chunks[:len(chunks)-1], "/")
			return address, k
		}
	}

	return address, APIVersionUnknown
}

// NewEndpoint parses the given address to return a registry endpoint.  v can be used to
// specify a specific endpoint version
func NewEndpoint(index *registrytypes.IndexInfo, userAgent string, metaHeaders http.Header, v APIVersion) (*Endpoint, error) {
	tlsConfig, err := newTLSConfig(index.Name, index.Secure)
	if err != nil {
		return nil, err
	}

	endpoint, err := newEndpointFromStr(GetAuthConfigKey(index), tlsConfig, userAgent, metaHeaders)
	if err != nil {
		return nil, err
	}

	if v != APIVersionUnknown {
		endpoint.Version = v
	}
	if err := validateEndpoint(endpoint); err != nil {
		return nil, err
	}

	return endpoint, nil
}

func validateEndpoint(endpoint *Endpoint) error {
	logrus.Debugf("pinging registry endpoint %s", endpoint)

	// Try HTTPS ping to registry
	endpoint.URL.Scheme = "https"
	if _, err := endpoint.Ping(); err != nil {
		if endpoint.IsSecure {
			// If registry is secure and HTTPS failed, show user the error and tell them about `--insecure-registry`
			// in case that's what they need. DO NOT accept unknown CA certificates, and DO NOT fallback to HTTP.
			return fmt.Errorf("invalid registry endpoint %s: %v. If this private registry supports only HTTP or HTTPS with an unknown CA certificate, please add `--insecure-registry %s` to the daemon's arguments. In the case of HTTPS, if you have access to the registry's CA certificate, no need for the flag; simply place the CA certificate at /etc/docker/certs.d/%s/ca.crt", endpoint, err, endpoint.URL.Host, endpoint.URL.Host)
		}

		// If registry is insecure and HTTPS failed, fallback to HTTP.
		logrus.Debugf("Error from registry %q marked as insecure: %v. Insecurely falling back to HTTP", endpoint, err)
		endpoint.URL.Scheme = "http"

		var err2 error
		if _, err2 = endpoint.Ping(); err2 == nil {
			return nil
		}

		return fmt.Errorf("invalid registry endpoint %q. HTTPS attempt: %v. HTTP attempt: %v", endpoint, err, err2)
	}

	return nil
}

func newEndpoint(address url.URL, tlsConfig *tls.Config, userAgent string, metaHeaders http.Header) (*Endpoint, error) {
	endpoint := &Endpoint{
		IsSecure: (tlsConfig == nil || !tlsConfig.InsecureSkipVerify),
		URL:      new(url.URL),
		Version:  APIVersionUnknown,
	}

	*endpoint.URL = address

	// TODO(tiborvass): make sure a ConnectTimeout transport is used
	tr := NewTransport(tlsConfig)
	endpoint.client = HTTPClient(transport.NewTransport(tr, DockerHeaders(userAgent, metaHeaders)...))
	return endpoint, nil
}

func newEndpointFromStr(address string, tlsConfig *tls.Config, userAgent string, metaHeaders http.Header) (*Endpoint, error) {
	if !strings.HasPrefix(address, "http://") && !strings.HasPrefix(address, "https://") {
		address = "https://" + address
	}

	trimmedAddress, detectedVersion := scanForAPIVersion(address)

	uri, err := url.Parse(trimmedAddress)
	if err != nil {
		return nil, err
	}

	endpoint, err := newEndpoint(*uri, tlsConfig, userAgent, metaHeaders)
	if err != nil {
		return nil, err
	}

	endpoint.Version = detectedVersion
	return endpoint, nil
}

// Endpoint stores basic information about a registry endpoint.
type Endpoint struct {
	client         *http.Client
	URL            *url.URL
	Version        APIVersion
	IsSecure       bool
	AuthChallenges []*AuthorizationChallenge
	URLBuilder     *v2.URLBuilder
}

// Get the formatted URL for the root of this registry Endpoint
func (e *Endpoint) String() string {
	return fmt.Sprintf("%s/v%d/", e.URL, e.Version)
}

// VersionString returns a formatted string of this
// endpoint address using the given API Version.
func (e *Endpoint) VersionString(version APIVersion) string {
	return fmt.Sprintf("%s/v%d/", e.URL, version)
}

// Path returns a formatted string for the URL
// of this endpoint with the given path appended.
func (e *Endpoint) Path(path string) string {
	return fmt.Sprintf("%s/v%d/%s", e.URL, e.Version, path)
}

// Ping pings the remote endpoint with v2 and v1 pings to determine the API
// version. It returns a PingResult containing the discovered version. The
// PingResult also indicates whether the registry is standalone or not.
func (e *Endpoint) Ping() (PingResult, error) {
	// The ping logic to use is determined by the registry endpoint version.
	switch e.Version {
	case APIVersion1:
		return e.pingV1()
	case APIVersion2:
		return e.pingV2()
	}

	// APIVersionUnknown
	// We should try v2 first...
	e.Version = APIVersion2
	regInfo, errV2 := e.pingV2()
	if errV2 == nil {
		return regInfo, nil
	}

	// ... then fallback to v1.
	e.Version = APIVersion1
	regInfo, errV1 := e.pingV1()
	if errV1 == nil {
		return regInfo, nil
	}

	e.Version = APIVersionUnknown
	return PingResult{}, fmt.Errorf("unable to ping registry endpoint %s\nv2 ping attempt failed with error: %s\n v1 ping attempt failed with error: %s", e, errV2, errV1)
}

func (e *Endpoint) pingV1() (PingResult, error) {
	logrus.Debugf("attempting v1 ping for registry endpoint %s", e)

	if e.String() == IndexServer {
		// Skip the check, we know this one is valid
		// (and we never want to fallback to http in case of error)
		return PingResult{Standalone: false}, nil
	}

	req, err := http.NewRequest("GET", e.Path("_ping"), nil)
	if err != nil {
		return PingResult{Standalone: false}, err
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return PingResult{Standalone: false}, err
	}

	defer resp.Body.Close()

	jsonString, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return PingResult{Standalone: false}, fmt.Errorf("error while reading the http response: %s", err)
	}

	// If the header is absent, we assume true for compatibility with earlier
	// versions of the registry. default to true
	info := PingResult{
		Standalone: true,
	}
	if err := json.Unmarshal(jsonString, &info); err != nil {
		logrus.Debugf("Error unmarshalling the _ping PingResult: %s", err)
		// don't stop here. Just assume sane defaults
	}
	if hdr := resp.Header.Get("X-Docker-Registry-Version"); hdr != "" {
		logrus.Debugf("Registry version header: '%s'", hdr)
		info.Version = hdr
	}
	logrus.Debugf("PingResult.Version: %q", info.Version)

	standalone := resp.Header.Get("X-Docker-Registry-Standalone")
	logrus.Debugf("Registry standalone header: '%s'", standalone)
	// Accepted values are "true" (case-insensitive) and "1".
	if strings.EqualFold(standalone, "true") || standalone == "1" {
		info.Standalone = true
	} else if len(standalone) > 0 {
		// there is a header set, and it is not "true" or "1", so assume fails
		info.Standalone = false
	}
	logrus.Debugf("PingResult.Standalone: %t", info.Standalone)
	return info, nil
}

func (e *Endpoint) pingV2() (PingResult, error) {
	logrus.Debugf("attempting v2 ping for registry endpoint %s", e)

	req, err := http.NewRequest("GET", e.Path(""), nil)
	if err != nil {
		return PingResult{}, err
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return PingResult{}, err
	}
	defer resp.Body.Close()

	// The endpoint may have multiple supported versions.
	// Ensure it supports the v2 Registry API.
	var supportsV2 bool

HeaderLoop:
	for _, supportedVersions := range resp.Header[http.CanonicalHeaderKey("Docker-Distribution-API-Version")] {
		for _, versionName := range strings.Fields(supportedVersions) {
			if versionName == "registry/2.0" {
				supportsV2 = true
				break HeaderLoop
			}
		}
	}

	if !supportsV2 {
		return PingResult{}, fmt.Errorf("%s does not appear to be a v2 registry endpoint", e)
	}

	if resp.StatusCode == http.StatusOK {
		// It would seem that no authentication/authorization is required.
		// So we don't need to parse/add any authorization schemes.
		return PingResult{Standalone: true}, nil
	}

	if resp.StatusCode == http.StatusUnauthorized {
		// Parse the WWW-Authenticate Header and store the challenges
		// on this endpoint object.
		e.AuthChallenges = parseAuthHeader(resp.Header)
		return PingResult{}, nil
	}

	return PingResult{}, fmt.Errorf("v2 registry endpoint returned status %d: %q", resp.StatusCode, http.StatusText(resp.StatusCode))
}
