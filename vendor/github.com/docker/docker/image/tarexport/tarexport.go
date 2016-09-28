package tarexport

import (
	"github.com/docker/docker/image"
	"github.com/docker/docker/layer"
	"github.com/docker/docker/reference"
)

const (
	manifestFileName           = "manifest.json"
	legacyLayerFileName        = "layer.tar"
	legacyConfigFileName       = "json"
	legacyVersionFileName      = "VERSION"
	legacyRepositoriesFileName = "repositories"
)

type manifestItem struct {
	Config   string
	RepoTags []string
	Layers   []string
}

type tarexporter struct {
	is image.Store
	ls layer.Store
	rs reference.Store
}

// NewTarExporter returns new ImageExporter for tar packages
func NewTarExporter(is image.Store, ls layer.Store, rs reference.Store) image.Exporter {
	return &tarexporter{
		is: is,
		ls: ls,
		rs: rs,
	}
}
