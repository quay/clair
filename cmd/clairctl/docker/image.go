package docker

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/spf13/viper"
)

var errDisallowed = errors.New("analysing official images is not allowed")

//Image represent Image Manifest from Docker image, including the registry URL
type Image struct {
	Name     string
	Tag      string
	Registry string
	FsLayers []Layer
}

//Layer represent the digest of a image layer
type Layer struct {
	BlobSum string
	History string
}

const dockerImageRegex = "^(?:([^/]+)/)?(?:([^/]+)/)?([^@:/]+)(?:[@:](.+))?"
const DockerHub = "registry-1.docker.io"
const hubURI = "https://" + DockerHub + "/v2"

var IsLocal = false

func TmpLocal() string {
	return viper.GetString("clairctl.tempFolder")
}

// Parse is used to parse a docker image command
//
//Example:
//"register.com:5080/wemanity-belgium/alpine"
//"register.com:5080/wemanity-belgium/alpine:latest"
//"register.com:5080/alpine"
//"register.com/wemanity-belgium/alpine"
//"register.com/alpine"
//"register.com/wemanity-belgium/alpine:latest"
//"alpine"
//"wemanity-belgium/alpine"
//"wemanity-belgium/alpine:latest"
func Parse(image string) (Image, error) {
	imageRegex := regexp.MustCompile(dockerImageRegex)

	if imageRegex.MatchString(image) == false {
		return Image{}, fmt.Errorf("cannot parse image name: %v", image)
	}
	groups := imageRegex.FindStringSubmatch(image)

	registry, repository, name, tag := groups[1], groups[2], groups[3], groups[4]

	if tag == "" {
		tag = "latest"
	}

	if repository == "" && !strings.ContainsAny(registry, ":.") {
		repository, registry = registry, hubURI //Regex problem, if no registry in url, regex parse repository as registry, so need to invert it

	} else {
		//FIXME We need to move to https. <error: tls: oversized record received with length 20527>
		//Maybe using a `insecure-registry` flag in configuration
		if strings.Contains(registry, "docker") {
			registry = "https://" + registry + "/v2"

		} else {
			registry = "http://" + registry + "/v2"
		}
	}

	if repository != "" {
		name = repository + "/" + name
	}

	if strings.Contains(registry, "docker.io") && repository == "" {
		return Image{}, errDisallowed
	}

	return Image{
		Registry: registry,
		Name:     name,
		Tag:      tag,
	}, nil
}

// BlobsURI run Blobs URI as <registry>/<imageName>/blobs/<digest>
// eg: "http://registry:5000/v2/jgsqware/ubuntu-git/blobs/sha256:13be4a52fdee2f6c44948b99b5b65ec703b1ca76c1ab5d2d90ae9bf18347082e"
func (image Image) BlobsURI(digest string) string {
	return strings.Join([]string{image.Registry, image.Name, "blobs", digest}, "/")
}

func (image Image) String() string {
	return image.Registry + "/" + image.Name + ":" + image.Tag
}

func (image Image) AsJSON() (string, error) {
	b, err := json.Marshal(image)
	if err != nil {
		return "", fmt.Errorf("cannot marshal image: %v", err)
	}
	return string(b), nil
}
