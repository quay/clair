// Copyright 2016 clair authors
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

package nodejs

import (
	"strings"
	"unicode"
)

type operVersion struct {
	Oper    string
	Version string
}

type ovState string

const (
	ovStateInit    ovState = "init"
	ovStateOper    ovState = "operation"
	ovStateVersion ovState = "version"
)

func isOper(ch rune) bool {
	return ch == '>' || ch == '<' || ch == '='
}

func getOperVersions(content string) (ovs []operVersion) {
	state := ovStateInit
	begin := 0
	var ov operVersion
	for i, ch := range content {
		if unicode.IsSpace(ch) {
			continue
		}
		switch state {
		case ovStateInit:
			if isOper(ch) {
				state = ovStateOper
				begin = i
			} else {
				return nil
			}
		case ovStateOper:
			if !isOper(ch) {
				state = ovStateVersion
				ov.Oper = strings.TrimSpace(content[begin:i])
				begin = i
			}
		case ovStateVersion:
			if isOper(ch) {
				state = ovStateOper
				ov.Version = strings.TrimSpace(content[begin:i])
				ovs = append(ovs, ov)
				begin = i
			}
		}
	}
	if state == ovStateVersion {
		ov.Version = strings.TrimSpace(content[begin:len(content)])
		ovs = append(ovs, ov)
	}

	return
}
