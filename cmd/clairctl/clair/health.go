package clair

import "net/http"

//IsHealthy return Health clair result
func IsHealthy() bool {
	log.Debug("requesting health on: " + healthURI)
	response, err := http.Get(healthURI)
	if err != nil {
		log.Errorf("requesting Clair health: %v", err)
		return false
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return false
	}

	return true
}
