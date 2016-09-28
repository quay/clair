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

// Package testutil contains helper functions for writing tests.
package testutil

import (
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/cloud"
)

const (
	envProjID     = "GCLOUD_TESTS_GOLANG_PROJECT_ID"
	envPrivateKey = "GCLOUD_TESTS_GOLANG_KEY"
)

func ProjID() string {
	projID := os.Getenv(envProjID)
	if projID == "" {
		log.Fatal(envProjID + " must be set. See CONTRIBUTING.md for details.")
	}
	return projID
}

func TokenSource(ctx context.Context, scopes ...string) oauth2.TokenSource {
	key := os.Getenv(envPrivateKey)
	if key == "" {
		log.Fatal(envPrivateKey + " must be set. See CONTRIBUTING.md for details.")
	}
	jsonKey, err := ioutil.ReadFile(key)
	if err != nil {
		log.Fatalf("Cannot read the JSON key file, err: %v", err)
	}
	conf, err := google.JWTConfigFromJSON(jsonKey, scopes...)
	if err != nil {
		log.Fatalf("google.JWTConfigFromJSON: %v", err)
	}
	return conf.TokenSource(ctx)
}

// TODO(djd): Delete this function when it's no longer used.
func Context(scopes ...string) context.Context {
	ctx := oauth2.NoContext
	ts := TokenSource(ctx, scopes...)
	return cloud.NewContext(ProjID(), oauth2.NewClient(ctx, ts))
}

// TODO(djd): Delete this function when it's no longer used.
func NoAuthContext() context.Context {
	return cloud.NewContext(ProjID(), &http.Client{Transport: http.DefaultTransport})
}
