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

// Interface to represent a location within Source.
type Location interface {
	GetLine() int   // 1-based line number within source.
	GetColumn() int // 0-based column number within source.
}

// Helper type to manually construct a location.
type RawLocation struct {
	line   int
	column int
}

// Ensure the RawLocation implements the Location interface.
var _ Location = &RawLocation{}

// Create a new location.
func NewLocation(line int, column int) Location {
	return &RawLocation{line: line, column: column}
}

func (l *RawLocation) GetLine() int {
	return l.line
}

func (l *RawLocation) GetColumn() int {
	return l.column
}
