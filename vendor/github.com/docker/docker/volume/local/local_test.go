package local

import (
	"io/ioutil"
	"os"
	"runtime"
	"testing"
)

func TestRemove(t *testing.T) {
	// TODO Windows: Investigate why this test fails on Windows under CI
	//               but passes locally.
	if runtime.GOOS == "windows" {
		t.Skip("Test failing on Windows CI")
	}
	rootDir, err := ioutil.TempDir("", "local-volume-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(rootDir)

	r, err := New(rootDir, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	vol, err := r.Create("testing", nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := r.Remove(vol); err != nil {
		t.Fatal(err)
	}

	vol, err = r.Create("testing2", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(vol.Path()); err != nil {
		t.Fatal(err)
	}

	if err := r.Remove(vol); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(vol.Path()); err != nil && !os.IsNotExist(err) {
		t.Fatal("volume dir not removed")
	}

	if l, _ := r.List(); len(l) != 0 {
		t.Fatal("expected there to be no volumes")
	}
}

func TestInitializeWithVolumes(t *testing.T) {
	rootDir, err := ioutil.TempDir("", "local-volume-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(rootDir)

	r, err := New(rootDir, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	vol, err := r.Create("testing", nil)
	if err != nil {
		t.Fatal(err)
	}

	r, err = New(rootDir, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	v, err := r.Get(vol.Name())
	if err != nil {
		t.Fatal(err)
	}

	if v.Path() != vol.Path() {
		t.Fatal("expected to re-initialize root with existing volumes")
	}
}

func TestCreate(t *testing.T) {
	rootDir, err := ioutil.TempDir("", "local-volume-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(rootDir)

	r, err := New(rootDir, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]bool{
		"name":                  true,
		"name-with-dash":        true,
		"name_with_underscore":  true,
		"name/with/slash":       false,
		"name/with/../../slash": false,
		"./name":                false,
		"../name":               false,
		"./":                    false,
		"../":                   false,
		"~":                     false,
		".":                     false,
		"..":                    false,
		"...":                   false,
	}

	for name, success := range cases {
		v, err := r.Create(name, nil)
		if success {
			if err != nil {
				t.Fatal(err)
			}
			if v.Name() != name {
				t.Fatalf("Expected volume with name %s, got %s", name, v.Name())
			}
		} else {
			if err == nil {
				t.Fatalf("Expected error creating volume with name %s, got nil", name)
			}
		}
	}
}

func TestValidateName(t *testing.T) {
	r := &Root{}
	names := map[string]bool{
		"/testvol":    false,
		"thing.d":     true,
		"hello-world": true,
		"./hello":     false,
		".hello":      false,
	}

	for vol, expected := range names {
		err := r.validateName(vol)
		if expected && err != nil {
			t.Fatalf("expected %s to be valid got %v", vol, err)
		}
		if !expected && err == nil {
			t.Fatalf("expected %s to be invalid", vol)
		}
	}
}
