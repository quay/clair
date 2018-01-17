// Copyright 2017 The Grafeas Authors. All rights reserved.
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

package name

import (
	"strings"
	"testing"
)

func TestNameRoundtrips(t *testing.T) {
	tests := []struct {
		part1 string
		part2 string
	}{
		{"a", "b"},
		{"foo", "foo"},
		{"blah-foo", "baz-inga"},
	}

	// Test two-part names
	for _, test := range tests {

		on := FormatOccurrence(test.part1, test.part2)
		if p1, p2, err := ParseOccurrence(on); err != nil {
			t.Errorf("ParseOccurrence %v; want (%v, %v), got error %v",
				on, test.part1, test.part2, err)
		} else if p1 != test.part1 || p2 != test.part2 {
			t.Errorf("ParseOccurrence %v; want (%v, %v), got (%v, %v)",
				on, test.part1, test.part2, p1, p2)
		}
		if rt, p1, p2, err := ParseResourceKindAndResource(on); err != nil {
			t.Errorf("ParseResourceKindAndResource %v; want (%v, %v, %v), got error %v",
				on, Occurrence, test.part1, test.part2, err)
		} else if rt != Occurrence || p1 != test.part1 || p2 != test.part2 {
			t.Errorf("ParseResourceKindAndResource %v; want (%v, %v, %v), got (%v, %v, %v)",
				on, Occurrence, test.part1, test.part2, rt, p1, p2)
		}

		if rt, p1, p2, err := ParseResourceKindAndResource(on); err != nil {
			t.Errorf("ParseResourceKindAndResource %v; want (%v, %v, %v), got error %v",
				on, Occurrence, test.part1, test.part2, err)
		} else if rt != Occurrence || p1 != test.part1 || p2 != test.part2 {
			t.Errorf("ParseResourceKindAndResource %v; want (%v, %v, %v), got (%v, %v, %v)",
				on, Occurrence, test.part1, test.part2, rt, p1, p2)
		}

		nn := FormatNote(test.part1, test.part2)
		if p1, p2, err := ParseNote(nn); err != nil {
			t.Errorf("ParseNote %v; want (%v, %v), got error %v",
				nn, test.part1, test.part2, err)
		} else if p1 != test.part1 || p2 != test.part2 {
			t.Errorf("ParseNote %v; want (%v, %v), got (%v, %v)",
				nn, test.part1, test.part2, p1, p2)
		}
		if rt, p1, p2, err := ParseResourceKindAndResource(nn); err != nil {
			t.Errorf("ParseResourceKindAndResource %v; want (%v, %v, %v), got error %v",
				on, Note, test.part1, test.part2, err)
		} else if rt != Note || p1 != test.part1 || p2 != test.part2 {
			t.Errorf("ParseResourceKindAndResource %v; want (%v, %v, %v), got (%v, %v, %v)",
				on, Note, test.part1, test.part2, rt, p1, p2)
		}

		opn := FormatOperation(test.part1, test.part2)
		if p1, p2, err := ParseOperation(opn); err != nil {
			t.Errorf("ParseOperation %v; got error %v, want (%v, %v)",
				opn, err, test.part1, test.part2)
		} else if p1 != test.part1 || p2 != test.part2 {
			t.Errorf("ParseOperation %v; got (%v, %v), want (%v, %v)",
				opn, p1, p2, test.part1, test.part2)
		}
	}

	// Test one-part names
	for _, test := range tests {
		fn := FormatProject(test.part1)
		if p1, err := ParseProject(fn); err != nil {
			t.Errorf("ParseProject %v; want %v, got error %v",
				fn, test.part1, err)
		} else if p1 != test.part1 {
			t.Errorf("ParseProject %v; want %v, got %v",
				fn, test.part1, p1)
		}

	}
}

func TestParseNoteValidation(t *testing.T) {
	badNoteNames := []string{
		// Bad keyword
		"providers/foo/findings/bar",
		// Too few parts
		"providers/foo/notes",
		// Too many parts
		"providers/foo/notes/bar/baz",
		// Empty part
		"providers//notes/bar",
		"providers/foo/notes/",
		// Too long
		"providers/foo/occurrences/" + strings.Repeat("a", 101),
	}

	for _, test := range badNoteNames {
		if p1, p2, err := ParseNote(test); err == nil {
			t.Errorf("ParseNote %v; wanted error, got (%v, %v)",
				test, p1, p2)
		}
	}
}

func TestParseOccurrenceValidation(t *testing.T) {
	badOccurrenceNames := []string{
		// Bad keyword
		"providers/foo/occurrences/bar",
		// Bad keyword
		"projects/foo/results/bar",
		// Too few parts
		"projects/foo/occurrences",
		// Too many parts
		"projects/foo/occurrences/bar/baz",
		// Empty part
		"projects//occurrences/bar",
		"projects/foo/occurrences/",
	}

	for _, test := range badOccurrenceNames {
		if p1, p2, err := ParseOccurrence(test); err == nil {
			t.Errorf("ParseOccurrence %v; wanted error, got (%v, %v)",
				test, p1, p2)
		}
	}
}

func TestParseResourceKindAndResource(t *testing.T) {
	badResourceNames := []string{
		"providers/foo/findings/bar",
		"providers/foo/occurrences/bar",
		"foo/foo/bar/bar",
		"projects/foo/results/bar",
		"projects/foo/results",
		"projects/foo/notes",
		"projects/foo",
		"providers/foo/results",
		"providers/foo/notes",
		"providers/foo",
		"projects/foo/findings",
		"projects/foo",
		"projects/foo/occurrences",
	}
	for _, test := range badResourceNames {
		if t1, p, r, err := ParseResourceKindAndResource(test); err == nil {
			t.Errorf("ParseResourceTypeAndResource %v; wanted error, got (%v, %v, %v)",
				test, t1, p, r)
		}
	}
}

func TestParseOperations(t *testing.T) {
	badResourceNames := []string{
		"providers/foo/operations/bar",
		"providers/foo/operations/bar",
		"foo/foo/bar/bar",
		"projects/foo/providers/bar",
		"providers/foo/projects/bar",
		"projects/foo/providers/bar/operations/baz",
		"operations/foo",
		"providers/-/projects/-/operations/abc",
		"providers//projects//operations/",
		"providers/foo/projects/bar/operations/" + strings.Repeat("a", 101),
	}
	for _, test := range badResourceNames {
		if t1, r, err := ParseOperation(test); err == nil {
			t.Errorf("ParseOperation %v; got (%v, %v), wanted error",
				test, t1, r)
		}
	}
}

func TestOccurrenceErrorMessage(t *testing.T) {
	want := "projects/{project_id}/occurrences/{entity_id}"
	if _, _, err := ParseOccurrence("providers/foo/notes/bar"); !strings.Contains(err.Error(), "projects/{project_id}/occurrences/{entity_id}") {
		t.Fatalf("bad error msg, got %q want it to contain %q", err, want)
	}
}

func TestParseResourceKindAndProjectPath(t *testing.T) {
	badResourcePaths := []string{
		"providers/foo/operations/bar",
		"providers/foo/operations/bar",
		"foo/foo/bar/bar",
		"projects/foo/providers/bar",
		"providers/foo/projects/bar",
		"projects/foo/providers/bar/operations/baz",
		"projects/foo/operations/bar",
		"projects/foo/occurrences/bar",
		"projects/foo/notes/bar",
		"operations/foo",
		"providers/-/projects/-/operations/abc",
		"providers//projects//operations/",
		"providers/foo/projects/bar/operations/" + strings.Repeat("a", 101),
	}
	for _, test := range badResourcePaths {
		if t1, r, err := ParseResourceKindAndProject(test); err == nil {
			t.Errorf("ParseResourceKindAndProject %v; got (%v, %v), wanted error",
				test, t1, r)
		}
	}

	goodResourcePaths := []string{
		"projects/foo/occurrences",
		"projects/foo/operations",
		"projects/foo/notes",
	}
	for _, test := range goodResourcePaths {
		if t1, r, err := ParseResourceKindAndProject(test); err != nil {
			t.Errorf("ParseResourceKindAndProject %v; got (%v, %v, %v), wanted success",
				test, t1, r, err)
		} else if r != "foo" {
			t.Errorf("ParseResourceKindAndProject %v; got %v, wanted foo", test, t1)
		}
	}
}

func TestParseProjectValidation(t *testing.T) {
	badProjectNames := []string{
		// Bad keyword
		"providers/foo/",
		// Trailing slash
		"projects/foo/",
		// Last part non-empty
		"projects/foo/baz",
		// Too many parts
		"projects/foo/baz/asdf",
		// Empty part
		"projects//",
	}

	for _, test := range badProjectNames {
		if p1, err := ParseProject(test); err == nil {
			t.Errorf("ParseProject %v; wanted error, got %v",
				test, p1)
		}
	}
}
