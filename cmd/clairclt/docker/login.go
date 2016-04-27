package docker

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/coreos/clair/cmd/clairclt/docker/httpclient"
)

//Pull Image from Registry or Hub depending on image name
func Login(registry string) (bool, error) {

	logrus.Info("log in: ", registry)

	if strings.Contains(registry, "docker") {
		registry = "https://" + registry + "/v2"

	} else {
		registry = "http://" + registry + "/v2"
	}

	client := httpclient.Get()
	request, err := http.NewRequest("GET", registry, nil)
	response, err := client.Do(request)
	if err != nil {
		return false, fmt.Errorf("log in %v: %v", registry, err)
	}
	authorized := response.StatusCode != http.StatusUnauthorized
	if !authorized {
		logrus.Info("Unauthorized access")
		err := AuthenticateResponse(response, request)

		if err != nil {
			if err == ErrUnauthorized {
				authorized = false
			}
			return false, err
		} else {
			authorized = true
		}
	}

	return authorized, nil
}
