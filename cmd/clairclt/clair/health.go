package clair

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
)

func IsHealthy() bool {
	healthURI := strings.Replace(uri, "6060/v1", strconv.Itoa(healthPort), 1) + "/health"
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
