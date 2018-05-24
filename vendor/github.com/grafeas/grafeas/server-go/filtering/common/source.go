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
	"strings"
)

// Interface for filter source contents.
type Source interface {
	// The source content represented as a string, for example a single file,
	// textbox field, or url parameter.
	Content() string

	// Brief description of the source, such as a file name or ui element.
	Description() string

	// The character offsets at which lines occur. The zero-th entry should
	// refer to the break between the first and second line, or EOF if there
	// is only one line of source.
	LineOffsets() []int32

	// The raw character offset at which the a location exists given the
	// location line and column.
	// Returns the line offset and whether the location was found.
	CharacterOffset(location Location) (int32, bool)

	// Return a line of content from the source and whether the line was found.
	Snippet(line int) (string, bool)
}

// Ensure the StringSource implements the Source interface.
var _ Source = &StringSource{}

// StringSource type implementation of the Source interface.
type StringSource struct {
	contents    string
	description string
	lineOffsets []int32
}

// Return a new Source given the string contents and description.
func NewStringSource(contents string, description string) Source {
	// Compute line offsets up front as they are referred to frequently.
	lines := strings.Split(contents, "\n")
	offsets := make([]int32, len(lines))
	var offset int32 = 0
	for i, line := range lines {
		offset = offset + int32(len(line)) + 1
		offsets[int32(i)] = offset
	}
	return &StringSource{
		contents:    contents,
		description: description,
		lineOffsets: offsets,
	}
}

func (s *StringSource) Content() string {
	return s.contents
}

func (s *StringSource) Description() string {
	return s.description
}

func (s *StringSource) LineOffsets() []int32 {
	return s.lineOffsets
}

func (s *StringSource) CharacterOffset(location Location) (int32, bool) {
	if lineOffset, found := s.findLineOffset(location.GetLine()); found {
		return lineOffset + int32(location.GetColumn()), true
	}
	return -1, false
}

func (s *StringSource) Snippet(line int) (string, bool) {
	if charStart, found := s.findLineOffset(line); found {
		charEnd, found := s.findLineOffset(line + 1)
		if found {
			return s.contents[charStart : charEnd-1], true
		}
		return s.contents[charStart:], true
	}
	return "", false
}

func (s *StringSource) findLineOffset(line int) (int32, bool) {
	if line == 1 {
		return 0, true
	} else if line > 1 && line <= int(len(s.lineOffsets)) {
		offset := s.lineOffsets[line-2]
		return offset, true
	}
	return -1, false

}
