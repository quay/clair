package contentmanifest

// ContentManifest structure is based on file provided by OSBS
// The struct stores content metadata about the image
type ContentManifest struct {
	ContentSets []string         `json:"content_sets"`
	Metadata    ManifestMetadata `json:"metadata"`
}

// ManifestMetadata struct holds additional metadata about image
type ManifestMetadata struct {
	ImageLayerIndex int `json:"image_layer_index"`
}
