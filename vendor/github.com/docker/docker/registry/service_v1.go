package registry

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/docker/docker/reference"
	"github.com/docker/go-connections/tlsconfig"
)

func (s *Service) lookupV1Endpoints(repoName reference.Named) (endpoints []APIEndpoint, err error) {
	var cfg = tlsconfig.ServerDefault
	tlsConfig := &cfg
	nameString := repoName.FullName()
	if strings.HasPrefix(nameString, DefaultNamespace+"/") {
		endpoints = append(endpoints, APIEndpoint{
			URL:          DefaultV1Registry,
			Version:      APIVersion1,
			Official:     true,
			TrimHostname: true,
			TLSConfig:    tlsConfig,
		})
		return endpoints, nil
	}

	slashIndex := strings.IndexRune(nameString, '/')
	if slashIndex <= 0 {
		return nil, fmt.Errorf("invalid repo name: missing '/':  %s", nameString)
	}
	hostname := nameString[:slashIndex]

	tlsConfig, err = s.TLSConfig(hostname)
	if err != nil {
		return nil, err
	}

	endpoints = []APIEndpoint{
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   hostname,
			},
			Version:      APIVersion1,
			TrimHostname: true,
			TLSConfig:    tlsConfig,
		},
	}

	if tlsConfig.InsecureSkipVerify {
		endpoints = append(endpoints, APIEndpoint{ // or this
			URL: &url.URL{
				Scheme: "http",
				Host:   hostname,
			},
			Version:      APIVersion1,
			TrimHostname: true,
			// used to check if supposed to be secure via InsecureSkipVerify
			TLSConfig: tlsConfig,
		})
	}
	return endpoints, nil
}
