package docker

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Sirupsen/logrus"
	"github.com/coreos/clair/cmd/clairctl/config"
	"github.com/coreos/clair/cmd/clairctl/docker/httpclient"
)

//Pull Image from Registry or Hub depending on image name
func Pull(imageName string) (Image, error) {
	image, err := Parse(imageName)
	if err != nil {
		return Image{}, err
	}

	logrus.Info("pulling image: ", image)

	mURI := fmt.Sprintf("%v/%v/manifests/%v", image.Registry, image.Name, image.Tag)
	client := httpclient.Get()
	request, err := http.NewRequest("GET", mURI, nil)
	response, err := client.Do(request)
	if err != nil {
		return Image{}, fmt.Errorf("retrieving manifest: %v", err)
	}

	if response.StatusCode == http.StatusUnauthorized {
		logrus.Info("Pull is Unauthorized")
		err := AuthenticateResponse(response, request)

		if err != nil {
			return Image{}, fmt.Errorf("authenticating: %v", err)
		}
		response, err = client.Do(request)
		if err != nil {
			return Image{}, fmt.Errorf("retrieving manifest: %v", err)
		}
	}

	if response.StatusCode != 200 {
		switch response.StatusCode {
		case http.StatusUnauthorized:
			return Image{}, ErrUnauthorized
		case http.StatusNotFound:
			return Image{}, config.ErrLoginNotFound
		default:
			return Image{}, fmt.Errorf("receiving http error: %d", response.StatusCode)
		}
	}
	if err := image.parseManifest(response); err != nil {
		return Image{}, fmt.Errorf("parsing manifest: %v", err)
	}

	return image, nil
}

func (image *Image) parseManifest(response *http.Response) error {

	err := json.NewDecoder(response.Body).Decode(&image)

	if err != nil {
		return fmt.Errorf("reading manifest body: %v", err)
	}

	image.uniqueLayers()
	return nil
}

func (image *Image) uniqueLayers() {
	encountered := map[Layer]bool{}
	result := []Layer{}

	for index := range image.FsLayers {
		if encountered[image.FsLayers[index]] != true {
			encountered[image.FsLayers[index]] = true
			result = append(result, image.FsLayers[index])
		}
	}
	image.FsLayers = result
}
