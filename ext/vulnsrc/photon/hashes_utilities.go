package photon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/quay/clair/v3/pkg/commonerr"
	log "github.com/sirupsen/logrus"
)

// calculateHash calculates sha256 byte slice
// in io.Reader containing bytes information
func calculateHash(jsonReader io.Reader) (sha string, err error) {
	// Create a TeeReader so that we can unmarshal into JSON and write to a hash
	// digest at the same time.
	jsonSHA := sha256.New()
	teedJSONReader := io.TeeReader(jsonReader, jsonSHA)

	// Unmarshal JSON.
	var data []cve
	err = json.NewDecoder(teedJSONReader).Decode(&data)
	if err != nil {
		log.WithError(err).Error("could not unmarshal Photon's JSON")
		return "", commonerr.ErrCouldNotParse
	}
	hash := hex.EncodeToString(jsonSHA.Sum(nil))
	return hash, nil
}

// calculateNewCVEfilesHashes returns a map which has photon version for a key
// and a hash value of the data corresponding cve metadata as a value
func calculateNewHashes(responses map[string][]byte) (versionToHash map[string]string) {
	versionToHash = make(map[string]string, 5)

	for version := range responses {
		byteReader := bytes.NewReader(responses[version])
		newHash, err := calculateHash(byteReader)
		if err != nil {
			log.WithField("package", "Photon").Infof("Problem calculating the hash for version %v", version)
			newHash = ""
		} else {
			versionToHash[version] = newHash
		}
	}
	return
}

// extractOldHashes creates a map from latestHashes
// containing photon versions as keys and hashes
// of their corresponding cve metadata files
func extractOldHashes(latestHashes string) (versionToHash map[string]string) {
	if latestHashes == "" {
		return nil
	}
	versionToHash = make(map[string]string, 5)
	tuples := strings.Split(latestHashes, ";")

	for _, tuple := range tuples {
		if tuple == "" {
			continue
		}

		keyHashTuple := strings.Split(tuple, ":")
		versionToHash[keyHashTuple[0]] = keyHashTuple[1]
	}
	return versionToHash
}

// createNewUpdaterFlag creates new updater flag
// it takes all old versions and hashes and updates
// those versions in the versionsToBeUpdated slice
func createNewUpdaterFlag(oldVersionToHash map[string]string, newVersionToHash map[string]string,
	versionsToBeUpdated []string) (updaterFlag string) {

	if oldVersionToHash == nil && newVersionToHash == nil {
		return ""
	}
	updatedVersionHashes := make(map[string]string)
	// Initialize the updatedVersionHashes so it will
	// have infomation for all hashes of all previous cve files
	for oldVer, oldHash := range oldVersionToHash {
		updatedVersionHashes[oldVer] = oldHash
	}

	for _, version := range versionsToBeUpdated {
		updatedVersionHashes[version] = newVersionToHash[version]
	}
	// Sort version slice will be use to access the
	// updatedVersionHashes map in a sorted way
	sortVersions := make([]string, 0)
	for version, _ := range updatedVersionHashes {
		sortVersions = append(sortVersions, version)
	}
	sort.Strings(sortVersions)

	for _, version := range sortVersions {
		updaterFlag += fmt.Sprintf("%v:%v;", version, updatedVersionHashes[version])
	}
	return
}
