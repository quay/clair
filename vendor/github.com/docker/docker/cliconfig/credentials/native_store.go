package credentials

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/cliconfig"
	"github.com/docker/engine-api/types"
)

const remoteCredentialsPrefix = "docker-credential-"

// Standarize the not found error, so every helper returns
// the same message and docker can handle it properly.
var errCredentialsNotFound = errors.New("credentials not found in native keychain")

// command is an interface that remote executed commands implement.
type command interface {
	Output() ([]byte, error)
	Input(in io.Reader)
}

// credentialsRequest holds information shared between docker and a remote credential store.
type credentialsRequest struct {
	ServerURL string
	Username  string
	Password  string
}

// credentialsGetResponse is the information serialized from a remote store
// when the plugin sends requests to get the user credentials.
type credentialsGetResponse struct {
	Username string
	Password string
}

// nativeStore implements a credentials store
// using native keychain to keep credentials secure.
// It piggybacks into a file store to keep users' emails.
type nativeStore struct {
	commandFn func(args ...string) command
	fileStore Store
}

// NewNativeStore creates a new native store that
// uses a remote helper program to manage credentials.
func NewNativeStore(file *cliconfig.ConfigFile) Store {
	return &nativeStore{
		commandFn: shellCommandFn(file.CredentialsStore),
		fileStore: NewFileStore(file),
	}
}

// Erase removes the given credentials from the native store.
func (c *nativeStore) Erase(serverAddress string) error {
	if err := c.eraseCredentialsFromStore(serverAddress); err != nil {
		return err
	}

	// Fallback to plain text store to remove email
	return c.fileStore.Erase(serverAddress)
}

// Get retrieves credentials for a specific server from the native store.
func (c *nativeStore) Get(serverAddress string) (types.AuthConfig, error) {
	// load user email if it exist or an empty auth config.
	auth, _ := c.fileStore.Get(serverAddress)

	creds, err := c.getCredentialsFromStore(serverAddress)
	if err != nil {
		return auth, err
	}
	auth.Username = creds.Username
	auth.Password = creds.Password

	return auth, nil
}

// Store saves the given credentials in the file store.
func (c *nativeStore) Store(authConfig types.AuthConfig) error {
	if err := c.storeCredentialsInStore(authConfig); err != nil {
		return err
	}
	authConfig.Username = ""
	authConfig.Password = ""

	// Fallback to old credential in plain text to save only the email
	return c.fileStore.Store(authConfig)
}

// storeCredentialsInStore executes the command to store the credentials in the native store.
func (c *nativeStore) storeCredentialsInStore(config types.AuthConfig) error {
	cmd := c.commandFn("store")
	creds := &credentialsRequest{
		ServerURL: config.ServerAddress,
		Username:  config.Username,
		Password:  config.Password,
	}

	buffer := new(bytes.Buffer)
	if err := json.NewEncoder(buffer).Encode(creds); err != nil {
		return err
	}
	cmd.Input(buffer)

	out, err := cmd.Output()
	if err != nil {
		t := strings.TrimSpace(string(out))
		logrus.Debugf("error adding credentials - err: %v, out: `%s`", err, t)
		return fmt.Errorf(t)
	}

	return nil
}

// getCredentialsFromStore executes the command to get the credentials from the native store.
func (c *nativeStore) getCredentialsFromStore(serverAddress string) (types.AuthConfig, error) {
	var ret types.AuthConfig

	cmd := c.commandFn("get")
	cmd.Input(strings.NewReader(serverAddress))

	out, err := cmd.Output()
	if err != nil {
		t := strings.TrimSpace(string(out))

		// do not return an error if the credentials are not
		// in the keyckain. Let docker ask for new credentials.
		if t == errCredentialsNotFound.Error() {
			return ret, nil
		}

		logrus.Debugf("error adding credentials - err: %v, out: `%s`", err, t)
		return ret, fmt.Errorf(t)
	}

	var resp credentialsGetResponse
	if err := json.NewDecoder(bytes.NewReader(out)).Decode(&resp); err != nil {
		return ret, err
	}

	ret.Username = resp.Username
	ret.Password = resp.Password
	ret.ServerAddress = serverAddress
	return ret, nil
}

// eraseCredentialsFromStore executes the command to remove the server redentails from the native store.
func (c *nativeStore) eraseCredentialsFromStore(serverURL string) error {
	cmd := c.commandFn("erase")
	cmd.Input(strings.NewReader(serverURL))

	out, err := cmd.Output()
	if err != nil {
		t := strings.TrimSpace(string(out))
		logrus.Debugf("error adding credentials - err: %v, out: `%s`", err, t)
		return fmt.Errorf(t)
	}

	return nil
}
