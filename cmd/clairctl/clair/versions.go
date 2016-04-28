package clair

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

func Versions() (interface{}, error) {
	Config()
	response, err := http.Get(uri + "/versions")

	if err != nil {
		return nil, fmt.Errorf("requesting Clair version: %v", err)
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("reading Clair version body: %v", err)
	}

	var versionBody interface{}
	err = json.Unmarshal(body, &versionBody)

	if err != nil {
		return nil, fmt.Errorf("unmarshalling Clair version body: %v", err)
	}

	return versionBody, nil
}
