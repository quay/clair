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
	"testing"
)

const (
	UnexpectedValue   = "Expected '%v', got '%v'"
	UnexpectedSnippet = "Expected snippet '%s', got '%s'"
	SnippetNotFound   = "Expected snippet at line %d, but not found"
	SnippetFound      = "Found snippet at line %d, where none was expected"
)

// Test the error description method.
func TestStringSource_Description(t *testing.T) {
	contents := "example content\nsecond line"
	source := NewStringSource(contents, "description-test")
	// Verify the content
	if source.Content() != contents {
		t.Errorf(UnexpectedValue, contents, source.Content())
	}
	// Verify the description
	if source.Description() != "description-test" {
		t.Errorf(UnexpectedValue, "description-test", source.Description())
	}

	// Assert that the snippets on lines 1 & 2 are what was expected.
	if str2, found := source.Snippet(2); !found {
		t.Errorf(SnippetNotFound, 2)

	} else if str2 != "second line" {
		t.Errorf(UnexpectedSnippet, "second line", str2)
	}
	if str1, found := source.Snippet(1); !found {
		t.Errorf(SnippetNotFound, 1)

	} else if str1 != "example content" {
		t.Errorf(UnexpectedSnippet, "example content", str1)
	}
}

// Test the character offest to make sure that the offsets accurately reflect
// the location of a character in source.
func TestStringSource_CharacterOffset(t *testing.T) {
	contents := "c.d &&\n\t b.c.arg(10) &&\n\t test(10)"
	source := NewStringSource(contents, "offset-test")
	expectedLineOffsets := []int32{7, 24, 35}
	if len(expectedLineOffsets) != len(source.LineOffsets()) {
		t.Errorf("Expected list of size '%d', got a list of size '%d'",
			len(expectedLineOffsets), len(source.LineOffsets()))
	} else {
		for i, val := range expectedLineOffsets {
			if val != source.LineOffsets()[i] {
				t.Errorf("Expected line %d offset of %d, go %d",
					i, val, source.LineOffsets()[i])
			}
		}
	}
	// Ensure that selecting a set of characters across multiple lines works as
	// expected.
	charStart, _ := source.CharacterOffset(NewLocation(1, 2))
	charEnd, _ := source.CharacterOffset(NewLocation(3, 2))
	if "d &&\n\t b.c.arg(10) &&\n\t " != string(contents[charStart:charEnd]) {
		t.Errorf(UnexpectedValue, "d &&\n\t b.c.arg(10) &&\n\t ",
			string(contents[charStart:charEnd]))
	}
	if _, found := source.CharacterOffset(NewLocation(4, 0)); found {
		t.Error("Character offset was out of range of source, but still found.")
	}
}

// Test the computation of snippets, single lines of text, from a multiline
// source.
func TestStringSource_SnippetMultiline(t *testing.T) {
	source := NewStringSource("hello\nworld\nmy\nbub\n", "four-line-test")
	if str, found := source.Snippet(1); !found {
		t.Errorf(SnippetNotFound, 1)
	} else if str != "hello" {
		t.Errorf(UnexpectedSnippet, "hello", str)
	}
	if str2, found := source.Snippet(2); !found {
		t.Errorf(SnippetNotFound, 2)
	} else if str2 != "world" {
		t.Errorf(UnexpectedSnippet, "world", str2)
	}
	if str3, found := source.Snippet(3); !found {
		t.Errorf(SnippetNotFound, 3)
	} else if str3 != "my" {
		t.Errorf(UnexpectedSnippet, "my", str3)
	}
	if str4, found := source.Snippet(4); !found {
		t.Errorf(SnippetNotFound, 4)
	} else if str4 != "bub" {
		t.Errorf(UnexpectedSnippet, "bub", str4)
	}
	if str5, found := source.Snippet(5); !found {
		t.Errorf(SnippetNotFound, 5)
	} else if str5 != "" {
		t.Errorf(UnexpectedSnippet, "", str5)
	}
}

// Test the computation of snippets from a single line source.
func TestStringSource_SnippetSingleline(t *testing.T) {
	source := NewStringSource("hello, world", "one-line-test")
	if str, found := source.Snippet(1); !found {
		t.Errorf(SnippetNotFound, 1)

	} else if str != "hello, world" {
		t.Errorf(UnexpectedSnippet, "hello, world", str)
	}
	if str2, found := source.Snippet(2); found {
		t.Error(SnippetFound, 2)
	} else if str2 != "" {
		t.Error(UnexpectedSnippet, "", str2)
	}
}
