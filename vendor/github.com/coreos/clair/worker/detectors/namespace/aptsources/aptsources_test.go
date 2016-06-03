// Copyright 2015 clair authors
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

package aptsources

import (
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/worker/detectors/namespace"
)

var aptSourcesOSTests = []namespace.NamespaceTest{
	{
		ExpectedNamespace: database.Namespace{Name: "debian:unstable"},
		Data: map[string][]byte{
			"etc/os-release": []byte(
				`PRETTY_NAME="Debian GNU/Linux stretch/sid"
NAME="Debian GNU/Linux"
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support/"
BUG_REPORT_URL="https://bugs.debian.org/"`),
			"etc/apt/sources.list": []byte(`deb http://httpredir.debian.org/debian unstable main`),
		},
	},
}

func TestAptSourcesNamespaceDetector(t *testing.T) {
	namespace.TestNamespaceDetector(t, &AptSourcesNamespaceDetector{}, aptSourcesOSTests)
}
