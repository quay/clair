package archiver

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestZipAndUnzip(t *testing.T) {
	symmetricTest(t, ".zip", Zip, Unzip)
}

func symmetricTest(t *testing.T, ext string, cf CompressFunc, dcf DecompressFunc) {
	tmp, err := ioutil.TempDir("", "archiver")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	// Test creating archive
	outfile := filepath.Join(tmp, "test"+ext)
	err = cf(outfile, []string{"testdata"})
	if err != nil {
		t.Fatalf("making archive: didn't expect an error, but got: %v", err)
	}

	var expectedFileCount int
	filepath.Walk("testdata", func(fpath string, info os.FileInfo, err error) error {
		expectedFileCount++
		return nil
	})

	// Test extracting archive
	dest := filepath.Join(tmp, "extraction_test")
	os.Mkdir(dest, 0755)
	err = dcf(outfile, dest)
	if err != nil {
		t.Fatalf("extracting archive: didn't expect an error, but got: %v", err)
	}

	// If outputs equals inputs, we're good; traverse output files
	// and compare file names, file contents, and file count.

	var actualFileCount int
	filepath.Walk(dest, func(fpath string, info os.FileInfo, err error) error {
		if fpath == dest {
			return nil
		}
		actualFileCount++

		origPath, err := filepath.Rel(dest, fpath)
		if err != nil {
			t.Fatalf("%s: Error inducing original file path: %v", fpath, err)
		}

		if info.IsDir() {
			// stat dir instead of read file
			_, err := os.Stat(origPath)
			if err != nil {
				t.Fatalf("%s: Couldn't stat original directory (%s): %v",
					fpath, origPath, err)
			}
			return nil
		}

		expectedFileInfo, err := os.Stat(origPath)
		if err != nil {
			t.Fatalf("%s: Error obtaining original file info: %v", fpath, err)
		}
		expected, err := ioutil.ReadFile(origPath)
		if err != nil {
			t.Fatalf("%s: Couldn't open original file (%s) from disk: %v",
				fpath, origPath, err)
		}

		actualFileInfo, err := os.Stat(fpath)
		if err != nil {
			t.Fatalf("%s: Error obtaining actual file info: %v", fpath, err)
		}
		actual, err := ioutil.ReadFile(fpath)
		if err != nil {
			t.Fatalf("%s: Couldn't open new file from disk: %v", fpath, err)
		}

		if actualFileInfo.Mode() != expectedFileInfo.Mode() {
			t.Fatalf("%s: File mode differed between on disk and compressed",
				expectedFileInfo.Mode().String()+" : "+actualFileInfo.Mode().String())
		}
		if !bytes.Equal(expected, actual) {
			t.Fatalf("%s: File contents differed between on disk and compressed", origPath)
		}

		return nil
	})

	if got, want := actualFileCount, expectedFileCount; got != want {
		t.Fatalf("Expected %d resulting files, got %d", want, got)
	}
}
