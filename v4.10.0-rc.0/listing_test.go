package Documentation

import (
	"bufio"
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestListing fails if the SUMMARY.md falls out of sync with the markdown files
// in this directory.
func TestListing(t *testing.T) {
	// Check that this is the docs test.
	// These files are copied into the "book" directory, so when left around in
	// a work tree, test will run there as well.
	if _, err := os.Stat("index.html"); err == nil {
		t.Skip("skip listing check in compiled docs")
	}

	linkline, err := regexp.Compile(`\s*- \[.+\]\((.+)\)`)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open("SUMMARY.md")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	linked := []string{"SUMMARY.md"}
	s := bufio.NewScanner(f)
	for s.Scan() {
		ms := linkline.FindSubmatch(s.Bytes())
		switch {
		case ms == nil, len(ms) == 1:
			continue
		case len(ms) == 2:
			linked = append(linked, path.Clean(string(ms[1])))
		}
	}
	if err := s.Err(); err != nil {
		t.Error(err)
	}
	sort.Strings(linked)

	var files []string
	err = fs.WalkDir(os.DirFS("."), ".", func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir():
			return nil
		case path.Ext(d.Name()) != ".md":
			return nil
		}
		files = append(files, p)
		return nil
	})
	if err != nil {
		t.Error(err)
	}
	sort.Strings(files)

	if !cmp.Equal(linked, files) {
		t.Error(cmp.Diff(linked, files))
	}
}
