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
	"fmt"
	"io"
	"sort"
	"strings"
)

// A Node is a YAML Node which can be a Map, List or Scalar.
type Node interface {
	write(io.Writer, int, int)
}

// A Map is a YAML Mapping which maps Strings to Nodes.
type Map map[string]Node

// Key returns the value associeted with the key in the map.
func (node Map) Key(key string) Node {
	return node[key]
}

func (node Map) write(out io.Writer, firstind, nextind int) {
	indent := bytes.Repeat([]byte{' '}, nextind)
	ind := firstind

	width := 0
	scalarkeys := []string{}
	objectkeys := []string{}
	for key, value := range node {
		if _, ok := value.(Scalar); ok {
			if swid := len(key); swid > width {
				width = swid
			}
			scalarkeys = append(scalarkeys, key)
			continue
		}
		objectkeys = append(objectkeys, key)
	}
	sort.Strings(scalarkeys)
	sort.Strings(objectkeys)

	for _, key := range scalarkeys {
		value := node[key].(Scalar)
		out.Write(indent[:ind])
		fmt.Fprintf(out, "%-*s %s\n", width+1, key+":", string(value))
		ind = nextind
	}
	for _, key := range objectkeys {
		out.Write(indent[:ind])
		if node[key] == nil {
			fmt.Fprintf(out, "%s: <nil>\n", key)
			continue
		}
		fmt.Fprintf(out, "%s:\n", key)
		ind = nextind
		node[key].write(out, ind+2, ind+2)
	}
}

// A List is a YAML Sequence of Nodes.
type List []Node

// Get the number of items in the List.
func (node List) Len() int {
	return len(node)
}

// Get the idx'th item from the List.
func (node List) Item(idx int) Node {
	if idx >= 0 && idx < len(node) {
		return node[idx]
	}
	return nil
}

func (node List) write(out io.Writer, firstind, nextind int) {
	indent := bytes.Repeat([]byte{' '}, nextind)
	ind := firstind

	for _, value := range node {
		out.Write(indent[:ind])
		fmt.Fprint(out, "- ")
		ind = nextind
		value.write(out, 0, ind+2)
	}
}

// A Scalar is a YAML Scalar.
type Scalar string

// String returns the string represented by this Scalar.
func (node Scalar) String() string { return string(node) }

func (node Scalar) write(out io.Writer, ind, _ int) {
	fmt.Fprintf(out, "%s%s\n", strings.Repeat(" ", ind), string(node))
}

// Render returns a string of the node as a YAML document.  Note that
// Scalars will have a newline appended if they are rendered directly.
func Render(node Node) string {
	buf := bytes.NewBuffer(nil)
	node.write(buf, 0, 0)
	return buf.String()
}
