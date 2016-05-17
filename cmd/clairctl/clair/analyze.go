package clair

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/coreos/clair/api/v1"
)

//Analyze get Analysis os specified layer
func Analyze(id string) (v1.LayerEnvelope, error) {

	lURI := fmt.Sprintf("%v/layers/%v?vulnerabilities", uri, id)
	response, err := http.Get(lURI)
	if err != nil {
		return v1.LayerEnvelope{}, fmt.Errorf("analysing layer %v: %v", id, err)
	}

	defer response.Body.Close()
	var analysis v1.LayerEnvelope
	err = json.NewDecoder(response.Body).Decode(&analysis)
	if err != nil {
		return v1.LayerEnvelope{}, fmt.Errorf("reading layer analysis: %v", err)
	}
	if response.StatusCode != 200 {
		//TODO: should I show reponse body in case of error?
		return v1.LayerEnvelope{}, fmt.Errorf("receiving http error: %d", response.StatusCode)
	}

	return analysis, nil
}
