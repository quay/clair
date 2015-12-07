// Copyright 2015 clair authors
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

package database

import (
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/google/cayley"
)

const (
	fieldFlagValue = "value"
	flagNodePrefix = "flag"
)

// UpdateFlag creates a flag or update an existing flag's value
func UpdateFlag(name, value string) error {
	if name == "" || value == "" {
		log.Warning("could not insert a flag which has an empty name or value")
		return cerrors.NewBadRequestError("could not insert a flag which has an empty name or value")
	}

	// Initialize transaction
	t := cayley.NewTransaction()

	// Get current flag value
	currentValue, err := GetFlagValue(name)
	if err != nil {
		return err
	}

	// Build transaction
	name = flagNodePrefix + ":" + name
	if currentValue != "" {
		t.RemoveQuad(cayley.Triple(name, fieldFlagValue, currentValue))
	}
	t.AddQuad(cayley.Triple(name, fieldFlagValue, value))

	// Apply transaction
	if err = store.ApplyTransaction(t); err != nil {
		log.Errorf("failed transaction (UpdateFlag): %s", err)
		return ErrTransaction
	}

	// Return
	return nil
}

// GetFlagValue returns the value of the flag given by its name (or an empty string if the flag does not exist)
func GetFlagValue(name string) (string, error) {
	return toValue(cayley.StartPath(store, flagNodePrefix+":"+name).Out(fieldFlagValue))
}
