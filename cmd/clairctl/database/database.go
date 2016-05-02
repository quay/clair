package database

import (
	"fmt"

	"github.com/Sirupsen/logrus"
)

var registryMapping map[string]string

//InsertRegistryMapping insert the pair layerID,RegistryURI
func InsertRegistryMapping(layerDigest string, registryURI string) {
	logrus.Debugf("Saving %s[%s]", layerDigest, registryURI)
	registryMapping[layerDigest] = registryURI
}

//GetRegistryMapping return the registryURI corresponding to the layerID passed as parameter
func GetRegistryMapping(layerDigest string) (string, error) {
	registryURI, present := registryMapping[layerDigest]
	if !present {
		return "", fmt.Errorf("%v mapping not found", layerDigest)
	}
	return registryURI, nil
}

func init() {
	registryMapping = map[string]string{}
}
