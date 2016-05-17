package clair

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/coreos/clair/api/v1"
)

//ErrOSNotSupported is returned when Clair received a layer which on os not supported
var ErrOSNotSupported = errors.New("worker: OS and/or package manager are not supported")

//Push send a layer to Clair for analysis
func Push(layer v1.LayerEnvelope) error {
	lJSON, err := json.Marshal(layer)
	if err != nil {
		return fmt.Errorf("marshalling layer: %v", err)
	}

	lURI := fmt.Sprintf("%v/layers", uri)
	request, err := http.NewRequest("POST", lURI, bytes.NewBuffer(lJSON))
	if err != nil {
		return fmt.Errorf("creating 'add layer' request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := (&http.Client{}).Do(request)
	if err != nil {
		return fmt.Errorf("pushing layer to clair: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != 201 {
		if response.StatusCode == 422 {
			return OSNotSupported
		}
		return fmt.Errorf("receiving http error: %d", response.StatusCode)
	}

	return nil
}
