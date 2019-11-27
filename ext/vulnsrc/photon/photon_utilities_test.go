package photon

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDownloadPhotonCVEfiles_EmptyVersions(t *testing.T) {
	received, err := downloadPhotonCVEfiles(nil)
	if err != nil {
		assert.Fail(t, "Problem downloading Photon cve files with empty versions input!", err)
	}
	if len(received) != 0 {
		assert.Fail(t, "The received map doesn't contain an expected element!", "Want: nil \nHave: %v \n",
			received)
	}
}
