package photon

import (
	"encoding/json"
	"io"
	"io/ioutil"

	"github.com/quay/clair/v3/pkg/commonerr"
	log "github.com/sirupsen/logrus"
)

type versionsInfo struct {
	Versions []string `json:"branches"`
}

// parseCVEinfoJSON parses the json information into
// slice of cve-s
func parseCVEinfoJSON(jsonReader io.Reader) ([]cve, error) {
	body, err := ioutil.ReadAll(jsonReader)
	if err != nil {
		log.Fatal(err)
	}

	var vulnerabilities []cve
	err = json.Unmarshal(body, &vulnerabilities)
	if err != nil {
		log.WithError(err).Error("Error unmarshaling!")
		return nil, commonerr.ErrCouldNotParse
	}
	return vulnerabilities, nil
}

// parseVersions parses the versions information into
// slice of string
func parseVersions(jsonReader io.Reader) ([]string, error) {
	body, err := ioutil.ReadAll(jsonReader)
	if err != nil {
		log.Fatal(err)
	}

	var photonVersions versionsInfo
	err = json.Unmarshal(body, &photonVersions)
	if err != nil {
		log.WithError(err).Error("Error unmarshaling!")
		return nil, commonerr.ErrCouldNotParse
	}
	return photonVersions.Versions, nil
}
