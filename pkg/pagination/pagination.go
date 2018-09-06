// Copyright 2018 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package pagination implements a series of utilities for dealing with
// paginating lists of objects for an API.
package pagination

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"

	"github.com/fernet/fernet-go"
)

// ErrInvalidToken is returned when a token fails to Unmarshal because it was
// invalid or expired.
var ErrInvalidToken = errors.New("invalid or expired pagination token")

// ErrInvalidKeyString is returned when the string representing a key is malformed.
var ErrInvalidKeyString = errors.New("invalid pagination key string: must be 32-byte URL-safe base64")

// Key represents the key used to cryptographically secure the token
// being used to keep track of pages.
type Key struct {
	fkey *fernet.Key
}

// NewKey generates a new random pagination key.
func NewKey() (k Key, err error) {
	k.fkey = new(fernet.Key)
	err = k.fkey.Generate()
	return k, err
}

// KeyFromString creates the key for a given string.
//
// Strings must be 32-byte URL-safe base64 representations of the key bytes.
func KeyFromString(keyString string) (k Key, err error) {
	var fkey *fernet.Key
	fkey, err = fernet.DecodeKey(keyString)
	if err != nil {
		return Key{}, ErrInvalidKeyString
	}
	return Key{fkey}, err
}

// Must is a helper that wraps calls returning a Key and and error and panics
// if the error is non-nil.
func Must(k Key, err error) Key {
	if err != nil {
		panic(err)
	}
	return k
}

// String implements the fmt.Stringer interface for Key.
func (k Key) String() string {
	return k.fkey.Encode()
}

// MarshalToken encodes an interface into JSON bytes and encrypts it.
func (k Key) MarshalToken(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(v)
	if err != nil {
		return nil, err
	}

	return fernet.EncryptAndSign(buf.Bytes(), k.fkey)
}

// UnmarshalToken decrypts a token using provided key and decodes the result
// into the provided interface.
func (k Key) UnmarshalToken(token string, v interface{}) error {
	msg := fernet.VerifyAndDecrypt([]byte(token), time.Hour, []*fernet.Key{k.fkey})
	if msg == nil {
		return ErrInvalidToken
	}

	return json.NewDecoder(bytes.NewBuffer(msg)).Decode(&v)
}
