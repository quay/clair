package featurens_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurens"
	"github.com/coreos/clair/pkg/tarutil"

	_ "github.com/coreos/clair/ext/featurens/alpinerelease"
	_ "github.com/coreos/clair/ext/featurens/aptsources"
	_ "github.com/coreos/clair/ext/featurens/lsbrelease"
	_ "github.com/coreos/clair/ext/featurens/osrelease"
	_ "github.com/coreos/clair/ext/featurens/redhatrelease"
)

var namespaceDetectorTests = []struct {
	in  tarutil.FilesMap
	out []database.LayerNamespace
	err string
}{
	{
		in: tarutil.FilesMap{
			"etc/os-release": []byte(`
PRETTY_NAME="Debian GNU/Linux 8 (jessie)"
NAME="Debian GNU/Linux"
VERSION_ID="8"
VERSION="8 (jessie)"
ID=debian
HOME_URL="http://www.debian.org/"
SUPPORT_URL="http://www.debian.org/support/"
BUG_REPORT_URL="https://bugs.debian.org/"`),
			"etc/alpine-release": []byte(`3.3.4`),
		},
		out: []database.LayerNamespace{
			{database.Namespace{"debian:8", "dpkg"}, database.NewNamespaceDetector("os-release", "1.0")},
			{database.Namespace{"alpine:v3.3", "dpkg"}, database.NewNamespaceDetector("alpine-release", "1.0")},
		},
	},
}

func TestNamespaceDetector(t *testing.T) {
	for _, test := range namespaceDetectorTests {
		out, err := featurens.Detect(test.in, featurens.ListDetectors())
		if test.err != "" {
			assert.EqualError(t, err, test.err)
			return
		}

		database.AssertLayerNamespacesEqual(t, test.out, out)
	}
}
