// Copyright 2015 CoreOS, Inc.
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

package types

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

type URLsMap map[string]URLs

// NewURLsMap returns a URLsMap instantiated from the given string,
// which consists of discovery-formatted names-to-URLs, like:
// mach0=http://1.1.1.1:2380,mach0=http://2.2.2.2::2380,mach1=http://3.3.3.3:2380,mach2=http://4.4.4.4:2380
func NewURLsMap(s string) (URLsMap, error) {
	cl := URLsMap{}
	v, err := url.ParseQuery(strings.Replace(s, ",", "&", -1))
	if err != nil {
		return nil, err
	}
	for name, urls := range v {
		if len(urls) == 0 || urls[0] == "" {
			return nil, fmt.Errorf("empty URL given for %q", name)
		}
		us, err := NewURLs(urls)
		if err != nil {
			return nil, err
		}
		cl[name] = us
	}
	return cl, nil
}

// String returns NameURLPairs into discovery-formatted name-to-URLs sorted by name.
func (c URLsMap) String() string {
	pairs := make([]string, 0)
	for name, urls := range c {
		for _, url := range urls {
			pairs = append(pairs, fmt.Sprintf("%s=%s", name, url.String()))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, ",")
}

// URLs returns a list of all URLs.
// The returned list is sorted in ascending lexicographical order.
func (c URLsMap) URLs() []string {
	urls := make([]string, 0)
	for _, us := range c {
		for _, u := range us {
			urls = append(urls, u.String())
		}
	}
	sort.Strings(urls)
	return urls
}

func (c URLsMap) Len() int {
	return len(c)
}
