package clair

import (
	"net/http"

	"github.com/Sirupsen/logrus"
)

//IsHealthy return Health clair result
func IsHealthy() bool {
	logrus.Debugln("requesting health on: " + healthURI)
	response, err := http.Get(healthURI)
	defer response.Body.Close()

	if err != nil {
		logrus.Errorf("requesting Clair health: %v", err)
		return false
	}

	if response.StatusCode != http.StatusOK {
		return false
	}

	return true
}
