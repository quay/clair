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

package amzn

type UpdateInfo struct {
	ALASList []ALAS `xml:"update"`
}

type ALAS struct {
	Id          string    `xml:"id"`
	Updated     Updated   `xml:"updated"`
	Severity    string    `xml:"severity"`
	Description string    `xml:"description"`
	Packages    []Package `xml:"pkglist>collection>package"`
}

type Updated struct {
	Date string `xml:"date,attr"`
}

type Package struct {
	Name    string `xml:"name,attr"`
	Epoch   string `xml:"epoch,attr"`
	Version string `xml:"version,attr"`
	Release string `xml:"release,attr"`
}