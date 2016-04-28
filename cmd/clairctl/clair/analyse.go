package clair

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/coreos/clair/api/v1"
)

//Analyse get Analysis os specified layer
func Analyse(id string) (v1.LayerEnvelope, error) {

	lURI := fmt.Sprintf("%v/layers/%v?vulnerabilities", uri, id)
	// lURI := fmt.Sprintf("%v/layers/%v/vulnerabilities?minimumPriority=%v", uri, id, priority)
	response, err := http.Get(lURI)
	if err != nil {
		return v1.LayerEnvelope{}, fmt.Errorf("analysing layer %v: %v", id, err)
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)

	if err != nil {
		return v1.LayerEnvelope{}, fmt.Errorf("reading layer analysis: %v", err)
	}
	if response.StatusCode != 200 {
		return v1.LayerEnvelope{}, fmt.Errorf("%d - %s", response.StatusCode, string(body))
	}

	var analysis v1.LayerEnvelope

	err = json.Unmarshal(body, &analysis)
	if err != nil {
		return v1.LayerEnvelope{}, fmt.Errorf("unmarshalling layer analysis: %v", err)
	}
	return analysis, nil
}
