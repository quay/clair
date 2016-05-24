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
	"io/ioutil"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/worker/detectors/namespace"
)

var nodejsDkpgTests = []namespace.NamespaceTest{
	{
		ExpectedNamespace: database.Namespace{Name: "nodejs:all"},
		Data: map[string][]byte{
			"var/lib/dpkg/status": []byte(
				`Package: nodejs
Status: install ok installed
Priority: extra
Section: web
Installed-Size: 3043
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 0.10.25
Depends: libc-ares2 (>= 1.8.0), libc6 (>= 2.14), libssl1.0.0 (>= 1.0.1), libstdc++6 (>= 4.1.1), libv8-3.14.5, zlib1g (>= 1:1.1.4)
Homepage: http://nodejs.org/
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>`),
		},
	},
	{
		ExpectedNamespace: database.Namespace{Name: "nodejs:all"},
		Data: map[string][]byte{
			"var/lib/rpm/Packages": loadFileForTest("testdata/Packages"),
		},
	},
	{
		ExpectedNamespace: database.Namespace{Name: "nodejs:all"},
		Data: map[string][]byte{
			"usr/local/bin/node": []byte("<empty>"),
		},
	},
}

func TestNodejsNamespaceDetector(t *testing.T) {
	namespace.TestNamespaceDetector(t, &NodejsNamespaceDetector{}, nodejsDkpgTests)
}

func loadFileForTest(name string) []byte {
	_, filename, _, _ := runtime.Caller(0)
	d, _ := ioutil.ReadFile(filepath.Join(filepath.Dir(filename), name))
	return d
}
