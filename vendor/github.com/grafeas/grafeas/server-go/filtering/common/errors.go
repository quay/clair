// Copyright 2018 The Grafeas Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// package common defines elements common to parsing and other diagnostics.
package common

import (
	"fmt"
)

// Errors type which contains a list of errors observed during parsing.
type Errors struct {
	errors []Error
}

// Create a new instance of the Errors type.
func NewErrors() *Errors {
	return &Errors{
		errors: []Error{},
	}
}

// Report an error at a source location.
func (e *Errors) ReportError(s Source, l Location, format string, args ...interface{}) {
	err := Error{
		Source:   s,
		Location: l,
		Message:  fmt.Sprintf(format, args...),
	}
	e.errors = append(e.errors, err)
}

// Return this list of observed errors.
func (e *Errors) GetErrors() []Error {
	return e.errors[:]
}

// Convert the error set to a newline delimited string.
func (e *Errors) String() string {
	var result = ""
	for i, err := range e.errors {
		if i >= 1 {
			result += "\n"
		}
		result += err.String()
	}
	return result
}
