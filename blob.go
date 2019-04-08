// Copyright 2019 clair authors
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

package clair

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/coreos/clair/pkg/httputil"
)

func retrieveLayerBlob(ctx context.Context, path string, headers map[string]string) (io.ReadCloser, error) {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		httpHeaders := make(http.Header)
		for key, value := range headers {
			httpHeaders[key] = []string{value}
		}

		reader, err := httputil.GetWithContext(ctx, path, httpHeaders)
		if err != nil {
			return nil, err
		}

		return reader, nil
	}

	return os.Open(path)
}
