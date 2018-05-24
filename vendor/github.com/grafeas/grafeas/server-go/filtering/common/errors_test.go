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

// Test the reporting and recording of errors.
func TestErrors(t *testing.T) {
	source := NewStringSource("a.b\n&&arg(missing, paren", "errors-test")
	errors := NewErrors()
	errors.ReportError(source, NewLocation(1, 1), "No such field")
	if len(errors.GetErrors()) != 1 {
		t.Error("First eror not recorded")
	}
	errors.ReportError(source, NewLocation(2, 20), "Syntax error, missing paren")
	if len(errors.GetErrors()) != 2 {
		t.Error("Second error not recorded")
	}
	expected :=
		"ERROR: errors-test:1:2: No such field\n" +
			" | a.b\n" +
			" | .^\n" +
			"ERROR: errors-test:2:21: Syntax error, missing paren\n" +
			" | &&arg(missing, paren\n" +
			" | ....................^"
	actual := errors.String()
	if actual != expected {
		t.Errorf("Expected %s, received %s", expected, actual)
	}
}
