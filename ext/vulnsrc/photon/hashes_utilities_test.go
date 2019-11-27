package photon

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCalclateHash(t *testing.T) {
	testFilePath := "/testdata/cve_metadata.json"
	_, filename, _, _ := runtime.Caller(0)
	testFile, _ := os.Open(filepath.Join(filepath.Dir(filename), testFilePath))

	expectedHash := "b4a1877bbf70e861d3868fe65282b7183f6f4ce29aea057a0b8ac14ff5e1b9c5"
	receivedHash, err := calculateHash(testFile)
	if err != nil {
		assert.Fail(t, "Calculating the %v file hash failed with error %v!", testFilePath, err)
	}
	if receivedHash != expectedHash {
		assert.Fail(t, "Caluclated has of the file is not correct!", "Want: %v \n Have: %v \n",
			expectedHash, receivedHash)
	}
}

func readTestFile(currentFile, testFileName string) (data []byte, err error) {
	testFilePath := filepath.Join(filepath.Dir(currentFile), "/testdata/", testFileName)
	testFile, _ := os.Open(testFilePath)
	byteArr, err := ioutil.ReadAll(testFile)
	if err != nil {
		return nil, err
	}
	return byteArr, nil
}

func TestCalculateNewCVEfilesHashes(t *testing.T) {
	_, currentFile, _, _ := runtime.Caller(0)

	byteArr1, err := readTestFile(currentFile, "cve_metadata.json")
	if err != nil {
		assert.Fail(t, "Reading the test file cve_metadata.json failed!", err)
	}
	byteArr2, err := readTestFile(currentFile, "cve_metadata2.json")
	if err != nil {
		assert.Fail(t, "Reading the test file cve_metadata2.json failed!", err)
	}

	testData := map[string][]byte{
		"3.0": byteArr1,
		"1.0": byteArr2,
	}

	expectedCVEfilesHashes := map[string]string{
		"3.0": "b4a1877bbf70e861d3868fe65282b7183f6f4ce29aea057a0b8ac14ff5e1b9c5",
		"1.0": "193e3a5fc5d320d5f2fef3bb86445b705253c9cc217cd62e0381a7c46700418a",
	}
	receivedCVEfilesHashes := calculateNewHashes(testData)
	if !reflect.DeepEqual(expectedCVEfilesHashes, receivedCVEfilesHashes) {
		assert.Fail(t, "The caculateNewCVEfilesHashes function doesn't work as expected!", "Want: %v \n Have: %v \n",
			expectedCVEfilesHashes, receivedCVEfilesHashes)
	}
}

func TestExtractOldCVEfilesHashes(t *testing.T) {
	hashesInput := []string{
		"1.0:asf213dwadadafrsfaewdsdqwdfescc;2.1:dwadakdekkdmsmmmmmswqw;3.0:ldwadladlcdkwjqsjrgtj;",
		"",
		"1.0:asf213dwadadafrsfaewdsdqwdfescc;",
	}
	expectedOutput := []map[string]string{
		{
			"1.0": "asf213dwadadafrsfaewdsdqwdfescc",
			"2.1": "dwadakdekkdmsmmmmmswqw",
			"3.0": "ldwadladlcdkwjqsjrgtj",
		},
		nil,
		{
			"1.0": "asf213dwadadafrsfaewdsdqwdfescc",
		},
	}

	for i, input := range hashesInput {
		received := extractOldHashes(input)

		if !reflect.DeepEqual(expectedOutput[i], received) {
			assert.Fail(t, "The responce doesn't contain an expected element!", "Want: %v \nHave: %v \n",
				expectedOutput[i], received)
		}
	}
}

func TestCreateNewUpdaterFlag(t *testing.T) {
	commonOldVersionHashMap := map[string]string{
		"1.0": "asf213d",
		"2.0": "dwadakd",
		"3.0": "ldwadla",
	}
	inputsOldHashes := []map[string]string{
		nil,
		commonOldVersionHashMap,
		commonOldVersionHashMap,
		commonOldVersionHashMap,
		commonOldVersionHashMap,
		commonOldVersionHashMap,
		commonOldVersionHashMap,
	}
	inputNewHashes := []map[string]string{
		nil,
		nil,
		{
			"3.0": "wprsjk",
		},
		{
			"0.1": "wwwooo",
		},
		{
			"2.1": "kkkkkk",
		},
		{
			"4.0": "mamwms",
		},
		{
			"0.1": "wwwooo",
			"2.1": "kkkkkk",
			"3.0": "wprsjk",
			"4.0": "mamwms",
		},
	}

	inputVersionsToBeUpdated := [][]string{
		nil,
		nil,
		{
			"3.0",
		},
		{
			"0.1",
		},
		{
			"2.1",
		},
		{
			"4.0",
		},
		{
			"0.1",
			"2.1",
			"3.0",
			"4.0",
		},
	}

	expectedOutPut := []string{
		"",
		"1.0:asf213d;2.0:dwadakd;3.0:ldwadla;",
		"1.0:asf213d;2.0:dwadakd;3.0:wprsjk;",
		"0.1:wwwooo;1.0:asf213d;2.0:dwadakd;3.0:ldwadla;",
		"1.0:asf213d;2.0:dwadakd;2.1:kkkkkk;3.0:ldwadla;",
		"1.0:asf213d;2.0:dwadakd;3.0:ldwadla;4.0:mamwms;",
		"0.1:wwwooo;1.0:asf213d;2.0:dwadakd;2.1:kkkkkk;3.0:wprsjk;4.0:mamwms;",
	}

	for i, oldMap := range inputsOldHashes {
		received := createNewUpdaterFlag(oldMap, inputNewHashes[i], inputVersionsToBeUpdated[i])

		if received != expectedOutPut[i] {
			assert.Fail(t, "The responce is not the expected updaterFlag!", "Want: %v \nHave: %v \n",
				expectedOutPut[i], received)
		}
	}
}
