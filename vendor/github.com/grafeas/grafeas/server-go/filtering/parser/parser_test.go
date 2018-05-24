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

// package parser provides methods to parse filter sources to CEL-based ASTs.
package parser

import (
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	pb "github.com/golang/protobuf/proto"
	expr "github.com/google/cel-spec/proto/v1"
	"github.com/grafeas/grafeas/server-go/filtering/common"
)

const (
	DiagnosticsDelimiter = "\nDiagnostics:\n"
	NoResult             = "<no result>"
	InputOutputDelimiter = "\n==================================================\n"
	TestCaseDelimiter    = "\n\n"
)

type baseline struct {
	expected *expr.ParsedExpr
	errors   string
	source   common.Source
}

func TestParse_Complex(t *testing.T) {
	runBaselines(t, "complex")
}

func TestParse_Equality(t *testing.T) {
	runBaselines(t, "equality")
}

func TestParse_Error(t *testing.T) {
	runBaselines(t, "error")
}

func TestParse_Expression(t *testing.T) {
	runBaselines(t, "expression")
}

func TestParse_Function(t *testing.T) {
	runBaselines(t, "function")
}

func TestParse_Member(t *testing.T) {
	runBaselines(t, "member")
}

func TestParse_Unicode(t *testing.T) {
	runBaselines(t, "unicode")
}

func runBaselines(t *testing.T, filename string) {
	baselines, err := newTestBaselines(filename)
	if err != nil {
		t.Errorf("Baselines could not be read: %v", err)
		return
	}
	for _, baseline := range baselines {
		verifyBaseline(t, baseline)
	}
}

func verifyBaseline(t *testing.T, baseline baseline) {
	result, err := Parse(baseline.source)
	if err != nil {
		if err.String() != baseline.errors {
			t.Errorf("Expected error not equal to actual. expected: %s\nactual: %s\n",
				baseline.errors, err.String())
		}
	} else if !pb.Equal(baseline.expected, result) {
		t.Errorf("Expected proto not equal to actual. expected: %s\nactual: %s\n",
			pb.MarshalTextString(baseline.expected),
			pb.MarshalTextString(result))
	}
}

func newTestBaselines(filename string) ([]baseline, error) {
	bytes, err := ioutil.ReadFile(fmt.Sprintf("testdata/%s.baseline", filename))
	if err != nil {
		panic(fmt.Sprintf("Could not read provided file: %s", filename))
	}
	testCases := strings.Split(string(bytes), TestCaseDelimiter)
	baselines := make([]baseline, len(testCases))
	for i, testCase := range testCases {
		testCaseName := fmt.Sprintf("%s[%d]", filename, i)
		inputOutput := strings.Split(testCase, InputOutputDelimiter)
		input, output := inputOutput[0], inputOutput[1]
		baselines[i] = baseline{
			source:   common.NewStringSource(input, testCaseName),
			expected: &expr.ParsedExpr{},
		}
		resultOrError := strings.Split(output, DiagnosticsDelimiter)
		result := resultOrError[0]
		if result != NoResult {
			if err := pb.UnmarshalText(output, baselines[i].expected); err != nil {
				return nil, err
			}
		} else {
			baselines[i].errors = resultOrError[1]
		}
	}
	return baselines, nil
}
