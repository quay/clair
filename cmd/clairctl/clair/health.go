package clair

import (
	"fmt"
	"net/http"
	"os"

	"github.com/Sirupsen/logrus"
)

func IsHealthy() bool {
	logrus.Debugln("requesting health on: " + healthURI)
	response, err := http.Get(healthURI)
	if err != nil {

		fmt.Fprintf(os.Stderr, "requesting Clair health: %v", err)
		return false
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return false
	}

	return true
}
