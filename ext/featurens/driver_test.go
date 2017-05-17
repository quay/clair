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

type MultipleNamespaceTestData struct {
	Files              tarutil.FilesMap
	ExpectedNamespaces []database.Namespace
}

func assertnsNameEqual(t *testing.T, nslist_expected, nslist []database.Namespace) {
	assert.Equal(t, len(nslist_expected), len(nslist))
	expected := map[string]struct{}{}
	input := map[string]struct{}{}
	// compare the two sets
	for i := range nslist_expected {
		expected[nslist_expected[i].Name] = struct{}{}
		input[nslist[i].Name] = struct{}{}
	}
	assert.Equal(t, expected, input)
}

func testMultipleNamespace(t *testing.T, testData []MultipleNamespaceTestData) {
	for _, td := range testData {
		nslist, err := featurens.Detect(td.Files)
		assert.Nil(t, err)
		assertnsNameEqual(t, td.ExpectedNamespaces, nslist)
	}
}

func TestMultipleNamespaceDetector(t *testing.T) {
	testData := []MultipleNamespaceTestData{
		{
			ExpectedNamespaces: []database.Namespace{
				database.Namespace{Name: "debian:8", VersionFormat: "dpkg"},
				database.Namespace{Name: "alpine:v3.3", VersionFormat: "dpkg"},
			},
			Files: tarutil.FilesMap{
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
		},
	}
	testMultipleNamespace(t, testData)
}
