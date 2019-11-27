package photon

import (
	"io/ioutil"
	"net/http"

	"github.com/quay/clair/v3/pkg/commonerr"
	"github.com/quay/clair/v3/pkg/httputil"
	log "github.com/sirupsen/logrus"
)

// downloadFile downloads a particular file and checks
// wherever the download succeeded
func downloadFile(URL string) (response *http.Response, err error) {
	response, err = httputil.GetWithUserAgent(URL)
	if err != nil {
		log.WithError(err).Errorf("could not download the file %v", URL)
		return nil, commonerr.ErrCouldNotDownload
	}
	if !httputil.Status2xx(response) {
		log.WithField("StatusCode", response.StatusCode).Errorf("Failed to download download the file %v", URL)
		return nil, commonerr.ErrCouldNotDownload
	}
	return
}

// downloadPhotonCVEfiles downloads all cve metadata files
// for all versions provided in the versions slice
func downloadPhotonCVEfiles(versions []string) (responses map[string][]byte, err error) {
	responses = make(map[string][]byte)

	for _, version := range versions {
		URL := cveFilesURLlprefix + version + ".json"

		response, err := downloadFile(URL)
		if err != nil {
			log.Infof("Problems downloading file from link: %v\n Skipping Photon version %v", URL, version)
			continue
		}
		defer response.Body.Close()

		byteArr, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Infof("Problems reading response body!\n Skipping Photon version %v", version)
			continue
		}
		responses[version] = byteArr
	}
	return
}
