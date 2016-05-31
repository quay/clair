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

// Package services defines a set of service interfaces needed by Clair internally.
package services

import (
	"errors"
)

var (
	// ErrBackendException is an error that occurs when the service backend does
	// not work properly (ie. unreachable).
	ErrBackendException = errors.New("services: an error occured when querying the backend")

	// ErrInconsistent is an error that occurs when a service consistency check
	// fails (ie. when an entity which is supposed to be unique is detected twice)
	ErrInconsistent = errors.New("services: inconsistent state")
)

type Base interface {
	// # Miscellaneous
	// Ping returns the health status of the service.
	Ping() bool

	// Close closes the connection to the service and free any allocated resources.
	Close()
}
