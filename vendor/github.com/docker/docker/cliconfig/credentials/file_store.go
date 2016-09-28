package credentials

import (
	"strings"

	"github.com/docker/docker/cliconfig"
	"github.com/docker/engine-api/types"
)

// fileStore implements a credentials store using
// the docker configuration file to keep the credentials in plain text.
type fileStore struct {
	file *cliconfig.ConfigFile
}

// NewFileStore creates a new file credentials store.
func NewFileStore(file *cliconfig.ConfigFile) Store {
	return &fileStore{
		file: file,
	}
}

// Erase removes the given credentials from the file store.
func (c *fileStore) Erase(serverAddress string) error {
	delete(c.file.AuthConfigs, serverAddress)
	return c.file.Save()
}

// Get retrieves credentials for a specific server from the file store.
func (c *fileStore) Get(serverAddress string) (types.AuthConfig, error) {
	authConfig, ok := c.file.AuthConfigs[serverAddress]
	if !ok {
		// Maybe they have a legacy config file, we will iterate the keys converting
		// them to the new format and testing
		for registry, ac := range c.file.AuthConfigs {
			if serverAddress == convertToHostname(registry) {
				return ac, nil
			}
		}

		authConfig = types.AuthConfig{}
	}
	return authConfig, nil
}

// Store saves the given credentials in the file store.
func (c *fileStore) Store(authConfig types.AuthConfig) error {
	c.file.AuthConfigs[authConfig.ServerAddress] = authConfig
	return c.file.Save()
}

func convertToHostname(url string) string {
	stripped := url
	if strings.HasPrefix(url, "http://") {
		stripped = strings.Replace(url, "http://", "", 1)
	} else if strings.HasPrefix(url, "https://") {
		stripped = strings.Replace(url, "https://", "", 1)
	}

	nameParts := strings.SplitN(stripped, "/", 2)

	return nameParts[0]
}
