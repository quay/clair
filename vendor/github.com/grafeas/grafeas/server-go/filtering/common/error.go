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

// package common defines types common to parsing and other diagnostics.
package common

import (
	"fmt"
	"strings"
)

// Error type which references a location within source and a message.
type Error struct {
	Location Location
	Source   Source
	Message  string
}

// Stringer implementation that places errors in context with the source.
func (e *Error) String() string {
	var result = fmt.Sprintf("ERROR: %s:%d:%d: %s",
		e.Source.Description(),
		e.Location.GetLine(),
		e.Location.GetColumn()+1, // add one to the 0-based column for display
		e.Message)
	if snippet, found := e.Source.Snippet(e.Location.GetLine()); found {
		result += "\n | "
		result += snippet
		result += "\n | "
		result += strings.Repeat(".", e.Location.GetColumn())
		result += "^"
	}
	return result
}
