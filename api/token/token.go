// Copyright 2017 clair authors
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

// Package token implements encryption/decryption for json encoded interfaces
package token

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"

	"github.com/fernet/fernet-go"
)

// Unmarshal decrypts a token using provided key
// and decode the result into interface.
func Unmarshal(token string, key string, v interface{}) error {
	k, _ := fernet.DecodeKey(key)
	msg := fernet.VerifyAndDecrypt([]byte(token), time.Hour, []*fernet.Key{k})
	if msg == nil {
		return errors.New("invalid or expired pagination token")
	}

	return json.NewDecoder(bytes.NewBuffer(msg)).Decode(&v)
}

// Marshal encodes an interface into json bytes and encrypts it.
func Marshal(v interface{}, key string) ([]byte, error) {
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(v)
	if err != nil {
		return nil, err
	}

	k, _ := fernet.DecodeKey(key)
	return fernet.EncryptAndSign(buf.Bytes(), k)
}
