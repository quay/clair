package clair

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func Versions() (interface{}, error) {
	Config()
	response, err := http.Get(uri + "/versions")
	if err != nil {
		return nil, fmt.Errorf("requesting Clair version: %v", err)
	}
	defer response.Body.Close()

	var versionBody interface{}
	err = json.NewDecoder(response.Body).Decode(&versionBody)
	if err != nil {
		return nil, fmt.Errorf("reading Clair version body: %v", err)
	}
	return versionBody, nil
}
