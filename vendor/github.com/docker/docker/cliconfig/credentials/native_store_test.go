package credentials

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/docker/engine-api/types"
)

const (
	validServerAddress   = "https://index.docker.io/v1"
	invalidServerAddress = "https://foobar.example.com"
	missingCredsAddress  = "https://missing.docker.io/v1"
)

var errCommandExited = fmt.Errorf("exited 1")

// mockCommand simulates interactions between the docker client and a remote
// credentials helper.
// Unit tests inject this mocked command into the remote to control execution.
type mockCommand struct {
	arg   string
	input io.Reader
}

// Output returns responses from the remote credentials helper.
// It mocks those reponses based in the input in the mock.
func (m *mockCommand) Output() ([]byte, error) {
	in, err := ioutil.ReadAll(m.input)
	if err != nil {
		return nil, err
	}
	inS := string(in)

	switch m.arg {
	case "erase":
		switch inS {
		case validServerAddress:
			return nil, nil
		default:
			return []byte("error erasing credentials"), errCommandExited
		}
	case "get":
		switch inS {
		case validServerAddress:
			return []byte(`{"Username": "foo", "Password": "bar"}`), nil
		case missingCredsAddress:
			return []byte(errCredentialsNotFound.Error()), errCommandExited
		case invalidServerAddress:
			return []byte("error getting credentials"), errCommandExited
		}
	case "store":
		var c credentialsRequest
		err := json.NewDecoder(strings.NewReader(inS)).Decode(&c)
		if err != nil {
			return []byte("error storing credentials"), errCommandExited
		}
		switch c.ServerURL {
		case validServerAddress:
			return nil, nil
		default:
			return []byte("error storing credentials"), errCommandExited
		}
	}

	return []byte("unknown argument"), errCommandExited
}

// Input sets the input to send to a remote credentials helper.
func (m *mockCommand) Input(in io.Reader) {
	m.input = in
}

func mockCommandFn(args ...string) command {
	return &mockCommand{
		arg: args[0],
	}
}

func TestNativeStoreAddCredentials(t *testing.T) {
	f := newConfigFile(make(map[string]types.AuthConfig))
	f.CredentialsStore = "mock"

	s := &nativeStore{
		commandFn: mockCommandFn,
		fileStore: NewFileStore(f),
	}
	err := s.Store(types.AuthConfig{
		Username:      "foo",
		Password:      "bar",
		Email:         "foo@example.com",
		ServerAddress: validServerAddress,
	})

	if err != nil {
		t.Fatal(err)
	}

	if len(f.AuthConfigs) != 1 {
		t.Fatalf("expected 1 auth config, got %d", len(f.AuthConfigs))
	}

	a, ok := f.AuthConfigs[validServerAddress]
	if !ok {
		t.Fatalf("expected auth for %s, got %v", validServerAddress, f.AuthConfigs)
	}
	if a.Auth != "" {
		t.Fatalf("expected auth to be empty, got %s", a.Auth)
	}
	if a.Username != "" {
		t.Fatalf("expected username to be empty, got %s", a.Username)
	}
	if a.Password != "" {
		t.Fatalf("expected password to be empty, got %s", a.Password)
	}
	if a.Email != "foo@example.com" {
		t.Fatalf("expected email `foo@example.com`, got %s", a.Email)
	}
}

func TestNativeStoreAddInvalidCredentials(t *testing.T) {
	f := newConfigFile(make(map[string]types.AuthConfig))
	f.CredentialsStore = "mock"

	s := &nativeStore{
		commandFn: mockCommandFn,
		fileStore: NewFileStore(f),
	}
	err := s.Store(types.AuthConfig{
		Username:      "foo",
		Password:      "bar",
		Email:         "foo@example.com",
		ServerAddress: invalidServerAddress,
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if err.Error() != "error storing credentials" {
		t.Fatalf("expected `error storing credentials`, got %v", err)
	}

	if len(f.AuthConfigs) != 0 {
		t.Fatalf("expected 0 auth config, got %d", len(f.AuthConfigs))
	}
}

func TestNativeStoreGet(t *testing.T) {
	f := newConfigFile(map[string]types.AuthConfig{
		validServerAddress: {
			Email: "foo@example.com",
		},
	})
	f.CredentialsStore = "mock"

	s := &nativeStore{
		commandFn: mockCommandFn,
		fileStore: NewFileStore(f),
	}
	a, err := s.Get(validServerAddress)
	if err != nil {
		t.Fatal(err)
	}

	if a.Username != "foo" {
		t.Fatalf("expected username `foo`, got %s", a.Username)
	}
	if a.Password != "bar" {
		t.Fatalf("expected password `bar`, got %s", a.Password)
	}
	if a.Email != "foo@example.com" {
		t.Fatalf("expected email `foo@example.com`, got %s", a.Email)
	}
}

func TestNativeStoreGetMissingCredentials(t *testing.T) {
	f := newConfigFile(map[string]types.AuthConfig{
		validServerAddress: {
			Email: "foo@example.com",
		},
	})
	f.CredentialsStore = "mock"

	s := &nativeStore{
		commandFn: mockCommandFn,
		fileStore: NewFileStore(f),
	}
	_, err := s.Get(missingCredsAddress)
	if err != nil {
		// missing credentials do not produce an error
		t.Fatal(err)
	}
}

func TestNativeStoreGetInvalidAddress(t *testing.T) {
	f := newConfigFile(map[string]types.AuthConfig{
		validServerAddress: {
			Email: "foo@example.com",
		},
	})
	f.CredentialsStore = "mock"

	s := &nativeStore{
		commandFn: mockCommandFn,
		fileStore: NewFileStore(f),
	}
	_, err := s.Get(invalidServerAddress)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if err.Error() != "error getting credentials" {
		t.Fatalf("expected `error getting credentials`, got %v", err)
	}
}

func TestNativeStoreErase(t *testing.T) {
	f := newConfigFile(map[string]types.AuthConfig{
		validServerAddress: {
			Email: "foo@example.com",
		},
	})
	f.CredentialsStore = "mock"

	s := &nativeStore{
		commandFn: mockCommandFn,
		fileStore: NewFileStore(f),
	}
	err := s.Erase(validServerAddress)
	if err != nil {
		t.Fatal(err)
	}

	if len(f.AuthConfigs) != 0 {
		t.Fatalf("expected 0 auth configs, got %d", len(f.AuthConfigs))
	}
}

func TestNativeStoreEraseInvalidAddress(t *testing.T) {
	f := newConfigFile(map[string]types.AuthConfig{
		validServerAddress: {
			Email: "foo@example.com",
		},
	})
	f.CredentialsStore = "mock"

	s := &nativeStore{
		commandFn: mockCommandFn,
		fileStore: NewFileStore(f),
	}
	err := s.Erase(invalidServerAddress)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if err.Error() != "error erasing credentials" {
		t.Fatalf("expected `error erasing credentials`, got %v", err)
	}
}
