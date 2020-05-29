package contentmanifest

// MappingFile is a data struct for mapping file between repositories and CPEs
type MappingFile struct {
	Data map[string]Repo `json:"data"`
}

// Repo structure holds information about CPEs for given repo
type Repo struct {
	CPEs []string `json:"cpes"`
}
