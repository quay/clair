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

// Package health defines a standard healthcheck response format and expose
// a function that summarizes registered healthchecks.
package health

import (
	"fmt"
	"sync"
)

// Status defines a way to know the health status of a service
type Status struct {
	// IsEssential determines if the service is essential to the app, which can't
	// run in case of a failure
	IsEssential bool
	// IsHealthy defines whether the service is working or not
	IsHealthy bool
	// Details gives informations specific to the service
	Details interface{}
}

// A Healthchecker function is a method returning the Status of the tested service
type Healthchecker func() Status

var (
	healthcheckersLock sync.Mutex
	healthcheckers     = make(map[string]Healthchecker)
)

// RegisterHealthchecker registers a Healthchecker function which will be part of Healthchecks
func RegisterHealthchecker(name string, f Healthchecker) {
	if name == "" {
		panic("Could not register a Healthchecker with an empty name")
	}
	if f == nil {
		panic("Could not register a nil Healthchecker")
	}

	healthcheckersLock.Lock()
	defer healthcheckersLock.Unlock()

	if _, alreadyExists := healthcheckers[name]; alreadyExists {
		panic(fmt.Sprintf("Healthchecker '%s' is already registered", name))
	}
	healthcheckers[name] = f
}

// Healthcheck calls every registered Healthchecker and summarize their output
func Healthcheck() (bool, map[string]interface{}) {
	globalHealth := true

	statuses := make(map[string]interface{})
	for serviceName, serviceChecker := range healthcheckers {
		status := serviceChecker()

		globalHealth = globalHealth && (!status.IsEssential || status.IsHealthy)
		statuses[serviceName] = struct {
			IsHealthy bool
			Details   interface{} `json:",omitempty"`
		}{
			IsHealthy: status.IsHealthy,
			Details:   status.Details,
		}
	}

	return globalHealth, statuses
}
