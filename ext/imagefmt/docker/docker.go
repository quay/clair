// Copyright 2017 clair authors
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

// Package docker implements an imagefmt.Extractor for docker formatted
// container image layers.
package docker

import (
	"io"

	"github.com/coreos/clair/ext/imagefmt"
	"github.com/coreos/clair/pkg/tarutil"
)

type format struct{}

func init() {
	imagefmt.RegisterExtractor("docker", &format{})
}

func (f format) ExtractFiles(layerReader io.ReadCloser, toExtract []string) (tarutil.FilesMap, error) {
	return tarutil.ExtractFiles(layerReader, toExtract)
}
