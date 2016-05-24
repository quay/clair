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
	"bufio"
	"io/ioutil"
	"os"
	"regexp"
	"strings"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils"
	"github.com/coreos/clair/worker/detectors"
	"github.com/coreos/pkg/capnslog"
)

var (
	log = capnslog.NewPackageLogger("github.com/coreos/clair", "worker/detectors/packages")

	defaultNodejsVersion = "all"
	nodejsPkg            = "nodejs"
	nodejsNSRegexp       = regexp.MustCompile(`bin/(node|nodejs|npm)$`)
	nodejsNSRpmRegexp    = regexp.MustCompile(`^var/lib/rpm/Packages$`)
	nodejsNSDpkgRegexp   = regexp.MustCompile(`^var/lib/dpkg/status$`)
)

// NodejsNamespaceDetector implements NamespaceDetector and detects Nodejs
// from /var/lib/dpkg/status, /var/lib/rpm/Packages or node binary installed manually
type NodejsNamespaceDetector struct{}

func init() {
	detectors.RegisterNamespaceDetector("nodejs", &NodejsNamespaceDetector{})

}

func (detector *NodejsNamespaceDetector) Detect(data map[string][]byte) *database.Namespace {
	if ns := detectDpkgNodejs(data); ns != nil {
		return ns
	} else if ns := detectRpmNodejs(data); ns != nil {
		return ns
	} else if ns := detectNodejs(data); ns != nil {
		return ns
	}

	return nil
}

func detectNodejs(data map[string][]byte) *database.Namespace {
	for filename, _ := range data {
		if nodejsNSRegexp.MatchString(filename) {
			return &database.Namespace{Name: nodejsPkg + ":" + defaultNodejsVersion}
		}
	}

	return nil
}

func detectDpkgNodejs(data map[string][]byte) *database.Namespace {
	f, hasFile := data["var/lib/dpkg/status"]
	if !hasFile {
		return nil
	}

	scanner := bufio.NewScanner(strings.NewReader(string(f)))
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "Package: ") {
			if pkgName := strings.TrimSpace(strings.TrimPrefix(line, "Package: ")); pkgName == nodejsPkg {
				return &database.Namespace{Name: nodejsPkg + ":" + defaultNodejsVersion}
			}
		}
	}

	return nil
}

func detectRpmNodejs(data map[string][]byte) *database.Namespace {
	f, hasFile := data["var/lib/rpm/Packages"]
	if !hasFile {
		return nil
	}

	// Write the required "Packages" file to disk
	tmpDir, err := ioutil.TempDir(os.TempDir(), "rpm")
	defer os.RemoveAll(tmpDir)
	if err != nil {
		log.Errorf("could not create temporary folder for RPM %s detection: %s", nodejsPkg, err)
		return nil
	}

	err = ioutil.WriteFile(tmpDir+"/Packages", f, 0700)
	if err != nil {
		log.Errorf("could not create temporary file for RPM %s detection: %s", nodejsPkg, err)
		return nil
	}

	out, err := utils.Exec(tmpDir, "rpm", "--dbpath", tmpDir, "-qi", nodejsPkg)
	if err != nil {
		log.Errorf("could not query RPM %s: %s. output: %s", nodejsPkg, err, string(out))
		return nil
	}

	return &database.Namespace{Name: nodejsPkg + ":" + defaultNodejsVersion}
}

// GetRequiredFiles returns the list of files that are required for Detect()
func (detector *NodejsNamespaceDetector) GetRequiredFiles() []*regexp.Regexp {
	return []*regexp.Regexp{nodejsNSRegexp, nodejsNSRpmRegexp, nodejsNSDpkgRegexp}
}
