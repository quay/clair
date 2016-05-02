package database

import "testing"

func TestInsertRegistryMapping(t *testing.T) {
	layerID := "sha256:13be4a52fdee2f6c44948b99b5b65ec703b1ca76c1ab5d2d90ae9bf18347082e"
	registryURI := "registry:5000"
	InsertRegistryMapping(layerID, registryURI)

	if r := registryMapping[layerID]; r != registryURI {
		t.Errorf("InsertRegistryMapping(%q,%q) => %q, want %q", layerID, registryURI, r, registryURI)
	}
}

func TestGetRegistryMapping(t *testing.T) {
	layerID := "sha256:13be4a52fdee2f6c44948b99b5b65ec703b1ca76c1ab5d2d90ae9bf18347082e"
	registryURI := "registry:5000"
	InsertRegistryMapping(layerID, registryURI)

	if r, err := GetRegistryMapping(layerID); r != registryURI {

		if err != nil {
			t.Errorf("InsertRegistryMapping(%q,%q) failed => %v", layerID, registryURI, err)
		} else {
			t.Errorf("InsertRegistryMapping(%q,%q) => %q, want %q", layerID, registryURI, r, registryURI)
		}
	}
}
