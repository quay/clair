// Copyright 2013 Google, Inc.  All rights reserved.
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

package yaml

import (
	"bytes"
	"strings"
	"testing"
)

var parseTests = []struct {
	Input  string
	Output string
}{
	{
		Input:  "key1: val1\n",
		Output: "key1: val1\n",
	},
	{
		Input:  "key2 : val1\n",
		Output: "key2: val1\n",
	},
	{
		Input:  "key3:val1\n",
		Output: "key3:val1\n",
	},
	{
		Input:  "key4 :val1\n",
		Output: "key4 :val1\n",
	},
	{
		Input: "key: nest: val\n",
		Output: "key:\n" +
			"  nest: val\n",
	},
	{
		Input: "a: b: c: d\n" +
			"      # comment\n" +
			"      e: f\n" +
			"   g: h: i\n" +
			"\n" +
			"      j: k\n" +
			"# comment\n" +
			"   l: m\n" +
			"n: o\n" +
			"",
		Output: "n: o\n" +
			"a:\n" +
			"  l: m\n" +
			"  b:\n" +
			"    c: d\n" +
			"    e: f\n" +
			"  g:\n" +
			"    h: i\n" +
			"    j: k\n" +
			"",
	},
	{
		Input: "- item\n" +
			"",
		Output: "- item\n" +
			"",
	},
	{
		Input: "- item2\n" +
			"- item1\n" +
			"",
		Output: "- item2\n" +
			"- item1\n" +
			"",
	},
	{
		Input: "- - list1a\n" +
			"  - list1b\n" +
			"- - list2a\n" +
			"  - list2b\n" +
			"",
		Output: "- - list1a\n" +
			"  - list1b\n" +
			"- - list2a\n" +
			"  - list2b\n" +
			"",
	},
	{
		Input: "-   \n" +
			"  - - listA1a\n" +
			"    - listA1b\n" +
			"  - - listA2a\n" +
			"    - listA2b\n" +
			"-\n" +
			"  - - listB1a\n" +
			"    - listB1b\n" +
			"  - - listB2a\n" +
			"    - listB2b\n" +
			"",
		Output: "- - - listA1a\n" +
			"    - listA1b\n" +
			"  - - listA2a\n" +
			"    - listA2b\n" +
			"- - - listB1a\n" +
			"    - listB1b\n" +
			"  - - listB2a\n" +
			"    - listB2b\n" +
			"",
	},
	{
		Input: "  - keyA1a: aaa\n" +
			"    keyA1b: bbb\n" +
			"  - keyA2a: ccc\n" +
			"    keyA2b: ddd\n" +
			"  - keyB1a: eee\n" +
			"    keyB1b: fff\n" +
			"  - keyB2a: ggg\n" +
			"    keyB2b: hhh\n" +
			"",
		Output: "- keyA1a: aaa\n" +
			"  keyA1b: bbb\n" +
			"- keyA2a: ccc\n" +
			"  keyA2b: ddd\n" +
			"- keyB1a: eee\n" +
			"  keyB1b: fff\n" +
			"- keyB2a: ggg\n" +
			"  keyB2b: hhh\n" +
			"",
	},
	{
		Input: "japanese:\n" +
			" - ichi\n" +
			" - ni\n" +
			" - san\n" +
			"french:\n" +
			" - un\n" +
			" - deux\n" +
			" - trois\n" +
			"english:\n" +
			" - one\n" +
			" - two\n" +
			" - three\n" +
			"",
		Output: "english:\n" +
			"  - one\n" +
			"  - two\n" +
			"  - three\n" +
			"french:\n" +
			"  - un\n" +
			"  - deux\n" +
			"  - trois\n" +
			"japanese:\n" +
			"  - ichi\n" +
			"  - ni\n" +
			"  - san\n" +
			"",
	},
	{
		Input:  `test: "localhost:8080"`,
		Output: `test: "localhost:8080"` + "\n",
	},
}

func TestParse(t *testing.T) {
	for idx, test := range parseTests {
		buf := bytes.NewBufferString(test.Input)
		node, err := Parse(buf)
		if err != nil {
			t.Errorf("parse: %s", err)
		}
		if got, want := Render(node), test.Output; got != want {
			t.Errorf("---%d---", idx)
			t.Errorf("got: %q:\n%s", got, got)
			t.Errorf("want: %q:\n%s", want, want)
		}
	}
}

var getTypeTests = []struct {
	Value string
	Type  int
	Split int
}{
	{
		Value: "a: b",
		Type:  typMapping,
		Split: 1,
	},
	{
		Value: "- b",
		Type:  typSequence,
		Split: 1,
	},
}

func TestGetType(t *testing.T) {
	for idx, test := range getTypeTests {
		v, s := getType([]byte(test.Value))
		if got, want := v, test.Type; got != want {
			t.Errorf("%d. type(%q) = %s, want %s", idx, test.Value,
				typNames[got], typNames[want])
		}
		if got, want := s, test.Split; got != want {
			got0, got1 := test.Value[:got], test.Value[got:]
			want0, want1 := test.Value[:want], test.Value[want:]
			t.Errorf("%d. split is %s|%s, want %s|%s", idx,
				got0, got1, want0, want1)
		}
	}
}

func Test_MultiLineString(t *testing.T) {
	buf := bytes.NewBufferString("a : |\n  a\n  b\n\nc : d")
	node, err := Parse(buf)
	if err != nil {
		t.Error(err)
	} else {
		m := node.(Map)
		v := m["a"].(Scalar)
		v2 := strings.TrimSpace(string(v))
		if v2 != "a\nb" {
			t.Errorf("multi line parsed wrong thing: %v", v)
		}
	}
}
