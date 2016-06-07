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

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

import "github.com/kylelemons/go-gypsy/yaml"

var (
	file = flag.String("file", "config.yaml", "(Simple) YAML file to read")
)

func main() {
	cmd := os.Args[0]
	flag.Usage = func() {
		fmt.Println(`Usage:`, cmd, `[<options>] [<param> ...]

  All <param>s given on the commandline are looked up in
the config file "config.yaml" (or whatever is specified for -file).

Examples:
  $`, cmd, `mapping.key1 # = value1
    Get the key1 element of the "mapping" mapping

  $`, cmd, `config.server[1]
    Get the second (1th) element of the "server" list inside the "config" mapping

  $`, cmd, `mapping mapping.key1 config config.server config.admin[1].password
	Retrieve a bunch of options.  With the example yaml file, some of these
	options are errors, which will print the (text of the) actual Go error from
	node.Get

Options:`)
		flag.PrintDefaults()
	}

	flag.Parse()

	config, err := yaml.ReadFile(*file)
	if err != nil {
		log.Fatalf("readfile(%q): %s", *file, err)
	}

	params := flag.Args()

	width := 0
	for _, param := range params {
		if w := len(param); w > width {
			width = w
		}
	}

	for _, param := range params {
		val, err := config.Get(param)
		if err != nil {
			fmt.Printf("%-*s = %s\n", width, param, err)
			continue
		}
		fmt.Printf("%-*s = %q\n", width, param, val)
	}
}
