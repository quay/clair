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

// Package httputil implements common HTTP functionality used throughout the Clair codebase.
package httputil

import (
	"net"
	"net/http"
	"strings"

	"github.com/coreos/clair/pkg/version"
)

// GetWithUserAgent performs an HTTP GET with the proper Clair User-Agent.
func GetWithUserAgent(url string) (*http.Response, error) {
	client := &http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Clair/"+version.Version+" (https://github.com/coreos/clair)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// GetClientAddr returns the first value in X-Forwarded-For if it exists
// otherwise fall back to use RemoteAddr
func GetClientAddr(r *http.Request) string {
	addr := r.RemoteAddr
	if s := r.Header.Get("X-Forwarded-For"); s != "" {
		ips := strings.Split(s, ",")
		// assume the first one is the client address
		if len(ips) != 0 {
			// validate the ip
			if realIP := net.ParseIP(ips[0]); realIP != nil {
				addr = strings.TrimSpace(ips[0])
			}
		}
	}
	return addr
}

// Status2xx returns true if the response's status code is success (2xx)
func Status2xx(resp *http.Response) bool {
	return resp.StatusCode/100 == 2
}
