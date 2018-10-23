// Copyright 2018 clair authors
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

// Package fsutil contains utility functions for file system querying.
package fsutil

import (
	"os"
	"strings"
)

type dirFilter int

const (
	// All doesn't filter anything
	All dirFilter = iota
	// FilesOnly filters Dir function to return only files
	FilesOnly
	// DirectoriesOnly filters Dir function to return only directories
	DirectoriesOnly
)

// Readdir lists the files or folders under the given path and filter based on the
// dirFilter.
func Readdir(path string, filter dirFilter) ([]string, error) {
	dir, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer dir.Close()
	finfos, err := dir.Readdir(0)
	if err != nil {
		return nil, err
	}

	var files []string
	for _, info := range finfos {
		if filter == DirectoriesOnly && !info.IsDir() {
			continue
		}

		if filter == FilesOnly && info.IsDir() {
			continue
		}

		if strings.HasPrefix(info.Name(), ".") {
			continue
		}

		files = append(files, info.Name())
	}

	return files, nil
}
