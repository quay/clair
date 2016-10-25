// Copyright 2016 CoreOS, Inc.
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

// Package dockerdist provides helper methods for retrieving and parsing a
// information from a remote Docker repository.
package dockerdist

import (
	"errors"
	"log"
	"net/url"

	distlib "github.com/docker/distribution"
	"github.com/docker/distribution/digest"
	"github.com/docker/distribution/manifest/schema1"
	"github.com/docker/distribution/registry/client"
	"github.com/docker/docker/cliconfig"
	"github.com/docker/docker/distribution"
	"github.com/docker/docker/reference"
	"github.com/docker/docker/registry"
	"github.com/docker/engine-api/types"
	"github.com/docker/go-connections/tlsconfig"
	"github.com/spf13/viper"

	"golang.org/x/net/context"
)

// getRepositoryClient returns a client for performing registry operations against the given named
// image.
func getRepositoryClient(image reference.Named, insecure bool, scopes ...string) (distlib.Repository, error) {
	// Lookup the index information for the name.
	indexInfo, err := registry.ParseSearchIndexInfo(image.String())
	if err != nil {
		return nil, err
	}

	authConfig, err := GetAuthCredentials(image.String())
	if err != nil {
		return nil, err
	}

	repoInfo := &registry.RepositoryInfo{
		image,
		indexInfo,
		false,
	}

	metaHeaders := map[string][]string{}
	tlsConfig := tlsconfig.ServerDefault
	//TODO(jgsqware): fix TLS
	tlsConfig.InsecureSkipVerify = viper.GetBool("auth.insecureSkipVerify")

	url, err := url.Parse("https://" + image.Hostname())
	if insecure {
		url, err = url.Parse("http://" + image.Hostname())
	}
	if err != nil {
		return nil, err
	}

	endpoint := registry.APIEndpoint{
		URL:          url,
		Version:      registry.APIVersion2,
		Official:     false,
		TrimHostname: true,
		TLSConfig:    &tlsConfig,
	}
	ctx := context.Background()
	repo, _, err := distribution.NewV2Repository(ctx, repoInfo, endpoint, metaHeaders, &authConfig, scopes...)
	return repo, err
}

// getDigest returns the digest for the given image.
func getDigest(ctx context.Context, repo distlib.Repository, image reference.Named) (digest.Digest, error) {
	if withDigest, ok := image.(reference.Canonical); ok {
		return withDigest.Digest(), nil
	}

	// Get TagService.
	tagSvc := repo.Tags(ctx)

	// Get Tag name.
	tag := "latest"
	if withTag, ok := image.(reference.NamedTagged); ok {
		tag = withTag.Tag()
	}

	// Get Tag's Descriptor.
	descriptor, err := tagSvc.Get(ctx, tag)
	if err != nil {
		// Docker returns an UnexpectedHTTPResponseError if it cannot parse the JSON body of an
		// unexpected error. Unfortunately, HEAD requests *by definition* don't have bodies, so
		// Docker will return this error for non-200 HEAD requests. We therefore have to hack
		// around it... *sigh*.
		if _, ok := err.(*client.UnexpectedHTTPResponseError); ok {
			return "", errors.New("Received error when trying to fetch the specified tag: it might not exist or you do not have access")
		}

		return "", err
	}

	return descriptor.Digest, nil
}

// GetAuthCredentials returns the auth credentials (if any found) for the given repository, as found
// in the user's docker config.
func GetAuthCredentials(image string) (types.AuthConfig, error) {
	// Lookup the index information for the name.
	indexInfo, err := registry.ParseSearchIndexInfo(image)
	if err != nil {
		return types.AuthConfig{}, err
	}

	// Retrieve the user's Docker configuration file (if any).
	configFile, err := cliconfig.Load(cliconfig.ConfigDir())
	if err != nil {
		return types.AuthConfig{}, err
	}

	// Resolve the authentication information for the registry specified, via the config file.
	return registry.ResolveAuthConfig(configFile.AuthConfigs, indexInfo), nil
}

// DownloadManifest the manifest for the given image, using the given credentials.
func DownloadManifest(image string, insecure bool) (reference.Named, distlib.Manifest, error) {
	// Parse the image name as a docker image reference.
	named, err := reference.ParseNamed(image)
	if err != nil {
		return nil, nil, err
	}

	// Create a reference to a repository client for the repo.
	repo, err := getRepositoryClient(named, insecure, "pull")
	if err != nil {
		return nil, nil, err
	}

	// Get the digest.
	ctx := context.Background()
	digest, err := getDigest(ctx, repo, named)
	if err != nil {
		return nil, nil, err
	}

	// Retrieve the manifest for the tag.
	log.Printf("Downloading manifest for image %v", image)

	manSvc, err := repo.Manifests(ctx)
	if err != nil {
		return nil, nil, err
	}

	manifest, err := manSvc.Get(ctx, digest)
	if err != nil {
		return nil, nil, err
	}

	// Verify the manifest if it's signed.
	switch manifest.(type) {
	case *schema1.SignedManifest:
		_, verr := schema1.Verify(manifest.(*schema1.SignedManifest))
		if verr != nil {
			return nil, nil, verr
		}
	default:
		log.Printf("Could not verify manifest for image %v: not signed", image)
	}

	return named, manifest, nil
}

// DownloadV1Manifest the manifest for the given image in v1 schema format, using the given credentials.
func DownloadV1Manifest(imageName string, insecure bool) (reference.Named, schema1.SignedManifest, error) {
	image, manifest, err := DownloadManifest(imageName, insecure)

	if err != nil {
		return nil, schema1.SignedManifest{}, err
	}
	// Ensure that the manifest type is supported.
	switch manifest.(type) {
	case *schema1.SignedManifest:
		return image, *manifest.(*schema1.SignedManifest), nil
	default:
		return nil, schema1.SignedManifest{}, errors.New("only v1 manifests are currently supported")
	}
}
