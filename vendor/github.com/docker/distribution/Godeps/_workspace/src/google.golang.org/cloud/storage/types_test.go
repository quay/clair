// Copyright 2014 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package storage

import (
	"fmt"
	"net/http"
	"testing"

	"google.golang.org/cloud"
)

type fakeTransport struct{}

func (t *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("error handling request")
}

func TestErrorOnObjectsInsertCall(t *testing.T) {
	ctx := cloud.NewContext("project-id", &http.Client{
		Transport: &fakeTransport{}})
	wc := NewWriter(ctx, "bucketname", "filename1")
	wc.ContentType = "text/plain"
	if _, err := wc.Write([]byte("hello world")); err == nil {
		t.Errorf("expected error on write, got nil")
	}
	if err := wc.Close(); err == nil {
		t.Errorf("expected error on close, got nil")
	}
}
