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
	"testing"
)

var stringTests = []struct {
	Tree   Node
	Expect string
}{
	{
		Tree: Scalar("test"),
		Expect: `test
`,
	},
	{
		Tree: List{
			Scalar("One"),
			Scalar("Two"),
			Scalar("Three"),
		},
		Expect: `- One
- Two
- Three
`,
	},
	{
		Tree: Map{
			"phonetic":     Scalar("true"),
			"organization": Scalar("Navy"),
			"alphabet": List{
				Scalar("Alpha"),
				Scalar("Bravo"),
				Scalar("Charlie"),
			},
		},
		Expect: `organization: Navy
phonetic:     true
alphabet:
  - Alpha
  - Bravo
  - Charlie
`,
	},
	{
		Tree: Map{
			"answer": Scalar("42"),
			"question": List{
				Scalar("What do you get when you multiply six by nine?"),
				Scalar("How many roads must a man walk down?"),
			},
		},
		Expect: `answer: 42
question:
  - What do you get when you multiply six by nine?
  - How many roads must a man walk down?
`,
	},
	{
		Tree: List{
			Map{
				"name": Scalar("John Smith"),
				"age":  Scalar("42"),
			},
			Map{
				"name": Scalar("Jane Smith"),
				"age":  Scalar("45"),
			},
		},
		Expect: `- age:  42
  name: John Smith
- age:  45
  name: Jane Smith
`,
	},
	{
		Tree: List{
			List{Scalar("one"), Scalar("two"), Scalar("three")},
			List{Scalar("un"), Scalar("deux"), Scalar("trois")},
			List{Scalar("ichi"), Scalar("ni"), Scalar("san")},
		},
		Expect: `- - one
  - two
  - three
- - un
  - deux
  - trois
- - ichi
  - ni
  - san
`,
	},
	{
		Tree: Map{
			"yahoo":  Map{"url": Scalar("http://yahoo.com/"), "company": Scalar("Yahoo! Inc.")},
			"google": Map{"url": Scalar("http://google.com/"), "company": Scalar("Google, Inc.")},
		},
		Expect: `google:
  company: Google, Inc.
  url:     http://google.com/
yahoo:
  company: Yahoo! Inc.
  url:     http://yahoo.com/
`,
	},
}

func TestRender(t *testing.T) {
	for idx, test := range stringTests {
		if got, want := Render(test.Tree), test.Expect; got != want {
			t.Errorf("%d. got:\n%s\n%d. want:\n%s\n", idx, got, idx, want)
		}
	}
}
