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

package nvd

import "io"

// NestedReadCloser wraps an io.Reader and implements io.ReadCloser by closing every embed
// io.ReadCloser.
// It allows chaining io.ReadCloser together and still keep the ability to close them all in a
// simple manner.
type NestedReadCloser struct {
	io.Reader
	NestedReadClosers []io.ReadCloser
}

// Close closes the gzip.Reader and the underlying io.ReadCloser.
func (nrc *NestedReadCloser) Close() {
	for _, nestedReadCloser := range nrc.NestedReadClosers {
		nestedReadCloser.Close()
	}
}
