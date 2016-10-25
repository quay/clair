package clair

import "testing"

func TestInsertRegistryMapping(t *testing.T) {
	layerID := "sha256:13be4a52fdee2f6c44948b99b5b65ec703b1ca76c1ab5d2d90ae9bf18347082e"
	registryURI := "registry:5000"
	insertRegistryMapping(layerID, registryURI)

	if r := registryMapping[layerID]; r != "http://registry:5000/v2" {
		t.Errorf("insertRegistryMapping(%q,%q) => %q, want %q", layerID, registryURI, r, "http://registry:5000/v2")
	}
}

func TestGetRegistryMapping(t *testing.T) {
	layerID := "sha256:13be4a52fdee2f6c44948b99b5b65ec703b1ca76c1ab5d2d90ae9bf18347082e"
	registryURI := "registry:5000"
	insertRegistryMapping(layerID, registryURI)

	if r, err := GetRegistryMapping(layerID); r != "http://registry:5000/v2" {

		if err != nil {
			t.Errorf("GetRegistryMapping(%q) failed => %v", layerID, err)
		} else {
			t.Errorf("GetRegistryMapping(%q) => %q, want %q", layerID, registryURI, r)
		}
	}
}
