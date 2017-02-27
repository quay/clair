package reference

import (
	"testing"

	"github.com/docker/distribution/digestset"
	"github.com/opencontainers/go-digest"
)

func TestValidateReferenceName(t *testing.T) {
	validRepoNames := []string{
		"docker/docker",
		"library/debian",
		"debian",
		"docker.io/docker/docker",
		"docker.io/library/debian",
		"docker.io/debian",
		"index.docker.io/docker/docker",
		"index.docker.io/library/debian",
		"index.docker.io/debian",
		"127.0.0.1:5000/docker/docker",
		"127.0.0.1:5000/library/debian",
		"127.0.0.1:5000/debian",
		"thisisthesongthatneverendsitgoesonandonandonthisisthesongthatnev",

		// This test case was moved from invalid to valid since it is valid input
		// when specified with a hostname, it removes the ambiguity from about
		// whether the value is an identifier or repository name
		"docker.io/1a3f5e7d9c1b3a5f7e9d1c3b5a7f9e1d3c5b7a9f1e3d5d7c9b1a3f5e7d9c1b3a",
	}
	invalidRepoNames := []string{
		"https://github.com/docker/docker",
		"docker/Docker",
		"-docker",
		"-docker/docker",
		"-docker.io/docker/docker",
		"docker///docker",
		"docker.io/docker/Docker",
		"docker.io/docker///docker",
		"1a3f5e7d9c1b3a5f7e9d1c3b5a7f9e1d3c5b7a9f1e3d5d7c9b1a3f5e7d9c1b3a",
	}

	for _, name := range invalidRepoNames {
		_, err := ParseNormalizedNamed(name)
		if err == nil {
			t.Fatalf("Expected invalid repo name for %q", name)
		}
	}

	for _, name := range validRepoNames {
		_, err := ParseNormalizedNamed(name)
		if err != nil {
			t.Fatalf("Error parsing repo name %s, got: %q", name, err)
		}
	}
}

func TestValidateRemoteName(t *testing.T) {
	validRepositoryNames := []string{
		// Sanity check.
		"docker/docker",

		// Allow 64-character non-hexadecimal names (hexadecimal names are forbidden).
		"thisisthesongthatneverendsitgoesonandonandonthisisthesongthatnev",

		// Allow embedded hyphens.
		"docker-rules/docker",

		// Allow multiple hyphens as well.
		"docker---rules/docker",

		//Username doc and image name docker being tested.
		"doc/docker",

		// single character names are now allowed.
		"d/docker",
		"jess/t",

		// Consecutive underscores.
		"dock__er/docker",
	}
	for _, repositoryName := range validRepositoryNames {
		_, err := ParseNormalizedNamed(repositoryName)
		if err != nil {
			t.Errorf("Repository name should be valid: %v. Error: %v", repositoryName, err)
		}
	}

	invalidRepositoryNames := []string{
		// Disallow capital letters.
		"docker/Docker",

		// Only allow one slash.
		"docker///docker",

		// Disallow 64-character hexadecimal.
		"1a3f5e7d9c1b3a5f7e9d1c3b5a7f9e1d3c5b7a9f1e3d5d7c9b1a3f5e7d9c1b3a",

		// Disallow leading and trailing hyphens in namespace.
		"-docker/docker",
		"docker-/docker",
		"-docker-/docker",

		// Don't allow underscores everywhere (as opposed to hyphens).
		"____/____",

		"_docker/_docker",

		// Disallow consecutive periods.
		"dock..er/docker",
		"dock_.er/docker",
		"dock-.er/docker",

		// No repository.
		"docker/",

		//namespace too long
		"this_is_not_a_valid_namespace_because_its_lenth_is_greater_than_255_this_is_not_a_valid_namespace_because_its_lenth_is_greater_than_255_this_is_not_a_valid_namespace_because_its_lenth_is_greater_than_255_this_is_not_a_valid_namespace_because_its_lenth_is_greater_than_255/docker",
	}
	for _, repositoryName := range invalidRepositoryNames {
		if _, err := ParseNormalizedNamed(repositoryName); err == nil {
			t.Errorf("Repository name should be invalid: %v", repositoryName)
		}
	}
}

func TestParseRepositoryInfo(t *testing.T) {
	type tcase struct {
		RemoteName, FamiliarName, FullName, AmbiguousName, Domain string
	}

	tcases := []tcase{
		{
			RemoteName:    "fooo/bar",
			FamiliarName:  "fooo/bar",
			FullName:      "docker.io/fooo/bar",
			AmbiguousName: "index.docker.io/fooo/bar",
			Domain:        "docker.io",
		},
		{
			RemoteName:    "library/ubuntu",
			FamiliarName:  "ubuntu",
			FullName:      "docker.io/library/ubuntu",
			AmbiguousName: "library/ubuntu",
			Domain:        "docker.io",
		},
		{
			RemoteName:    "nonlibrary/ubuntu",
			FamiliarName:  "nonlibrary/ubuntu",
			FullName:      "docker.io/nonlibrary/ubuntu",
			AmbiguousName: "",
			Domain:        "docker.io",
		},
		{
			RemoteName:    "other/library",
			FamiliarName:  "other/library",
			FullName:      "docker.io/other/library",
			AmbiguousName: "",
			Domain:        "docker.io",
		},
		{
			RemoteName:    "private/moonbase",
			FamiliarName:  "127.0.0.1:8000/private/moonbase",
			FullName:      "127.0.0.1:8000/private/moonbase",
			AmbiguousName: "",
			Domain:        "127.0.0.1:8000",
		},
		{
			RemoteName:    "privatebase",
			FamiliarName:  "127.0.0.1:8000/privatebase",
			FullName:      "127.0.0.1:8000/privatebase",
			AmbiguousName: "",
			Domain:        "127.0.0.1:8000",
		},
		{
			RemoteName:    "private/moonbase",
			FamiliarName:  "example.com/private/moonbase",
			FullName:      "example.com/private/moonbase",
			AmbiguousName: "",
			Domain:        "example.com",
		},
		{
			RemoteName:    "privatebase",
			FamiliarName:  "example.com/privatebase",
			FullName:      "example.com/privatebase",
			AmbiguousName: "",
			Domain:        "example.com",
		},
		{
			RemoteName:    "private/moonbase",
			FamiliarName:  "example.com:8000/private/moonbase",
			FullName:      "example.com:8000/private/moonbase",
			AmbiguousName: "",
			Domain:        "example.com:8000",
		},
		{
			RemoteName:    "privatebasee",
			FamiliarName:  "example.com:8000/privatebasee",
			FullName:      "example.com:8000/privatebasee",
			AmbiguousName: "",
			Domain:        "example.com:8000",
		},
		{
			RemoteName:    "library/ubuntu-12.04-base",
			FamiliarName:  "ubuntu-12.04-base",
			FullName:      "docker.io/library/ubuntu-12.04-base",
			AmbiguousName: "index.docker.io/library/ubuntu-12.04-base",
			Domain:        "docker.io",
		},
	}

	for _, tcase := range tcases {
		refStrings := []string{tcase.FamiliarName, tcase.FullName}
		if tcase.AmbiguousName != "" {
			refStrings = append(refStrings, tcase.AmbiguousName)
		}

		var refs []NormalizedNamed
		for _, r := range refStrings {
			named, err := ParseNormalizedNamed(r)
			if err != nil {
				t.Fatal(err)
			}
			refs = append(refs, named)
		}

		for _, r := range refs {
			if expected, actual := tcase.FamiliarName, r.Familiar().Name(); expected != actual {
				t.Fatalf("Invalid normalized reference for %q. Expected %q, got %q", r, expected, actual)
			}
			if expected, actual := tcase.FullName, r.String(); expected != actual {
				t.Fatalf("Invalid canonical reference for %q. Expected %q, got %q", r, expected, actual)
			}
			if expected, actual := tcase.Domain, Domain(r); expected != actual {
				t.Fatalf("Invalid domain for %q. Expected %q, got %q", r, expected, actual)
			}
			if expected, actual := tcase.RemoteName, Path(r); expected != actual {
				t.Fatalf("Invalid remoteName for %q. Expected %q, got %q", r, expected, actual)
			}

		}
	}
}

func TestParseReferenceWithTagAndDigest(t *testing.T) {
	shortRef := "busybox:latest@sha256:86e0e091d0da6bde2456dbb48306f3956bbeb2eae1b5b9a43045843f69fe4aaa"
	nref, err := ParseNormalizedNamed(shortRef)
	if err != nil {
		t.Fatal(err)
	}
	if expected, actual := "docker.io/library/"+shortRef, nref.String(); actual != expected {
		t.Fatalf("Invalid parsed reference for %q: expected %q, got %q", nref, expected, actual)
	}

	ref := nref.Familiar()
	if _, isTagged := ref.(NamedTagged); !isTagged {
		t.Fatalf("Reference from %q should support tag", ref)
	}
	if _, isCanonical := ref.(Canonical); !isCanonical {
		t.Fatalf("Reference from %q should support digest", ref)
	}
	if expected, actual := shortRef, ref.String(); actual != expected {
		t.Fatalf("Invalid parsed reference for %q: expected %q, got %q", ref, expected, actual)
	}
}

func TestInvalidReferenceComponents(t *testing.T) {
	if _, err := ParseNormalizedNamed("-foo"); err == nil {
		t.Fatal("Expected WithName to detect invalid name")
	}
	ref, err := ParseNormalizedNamed("busybox")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WithTag(ref, "-foo"); err == nil {
		t.Fatal("Expected WithName to detect invalid tag")
	}
	if _, err := WithDigest(ref, digest.Digest("foo")); err == nil {
		t.Fatal("Expected WithDigest to detect invalid digest")
	}
}

func equalReference(r1, r2 Reference) bool {
	switch v1 := r1.(type) {
	case digestReference:
		if v2, ok := r2.(digestReference); ok {
			return v1 == v2
		}
	case repository:
		if v2, ok := r2.(repository); ok {
			return v1 == v2
		}
	case taggedReference:
		if v2, ok := r2.(taggedReference); ok {
			return v1 == v2
		}
	case canonicalReference:
		if v2, ok := r2.(canonicalReference); ok {
			return v1 == v2
		}
	case reference:
		if v2, ok := r2.(reference); ok {
			return v1 == v2
		}
	}
	return false
}

func TestParseAnyReference(t *testing.T) {
	tcases := []struct {
		Reference  string
		Equivalent string
		Expected   Reference
		Digests    []digest.Digest
	}{
		{
			Reference:  "redis",
			Equivalent: "docker.io/library/redis",
		},
		{
			Reference:  "redis:latest",
			Equivalent: "docker.io/library/redis:latest",
		},
		{
			Reference:  "docker.io/library/redis:latest",
			Equivalent: "docker.io/library/redis:latest",
		},
		{
			Reference:  "redis@sha256:dbcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9c",
			Equivalent: "docker.io/library/redis@sha256:dbcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9c",
		},
		{
			Reference:  "docker.io/library/redis@sha256:dbcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9c",
			Equivalent: "docker.io/library/redis@sha256:dbcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9c",
		},
		{
			Reference:  "dmcgowan/myapp",
			Equivalent: "docker.io/dmcgowan/myapp",
		},
		{
			Reference:  "dmcgowan/myapp:latest",
			Equivalent: "docker.io/dmcgowan/myapp:latest",
		},
		{
			Reference:  "docker.io/mcgowan/myapp:latest",
			Equivalent: "docker.io/mcgowan/myapp:latest",
		},
		{
			Reference:  "dmcgowan/myapp@sha256:dbcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9c",
			Equivalent: "docker.io/dmcgowan/myapp@sha256:dbcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9c",
		},
		{
			Reference:  "docker.io/dmcgowan/myapp@sha256:dbcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9c",
			Equivalent: "docker.io/dmcgowan/myapp@sha256:dbcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9c",
		},
		{
			Reference: "dbcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9c",
			Expected:  digestReference("sha256:dbcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9c"),
		},
		{
			Reference: "sha256:dbcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9c",
			Expected:  digestReference("sha256:dbcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9c"),
		},
		{
			Reference:  "dbcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9",
			Equivalent: "docker.io/library/dbcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9",
		},
		{
			Reference: "dbcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9",
			Expected:  digestReference("sha256:dbcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9c"),
			Digests: []digest.Digest{
				digest.Digest("sha256:dbcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9c"),
				digest.Digest("sha256:abcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9c"),
			},
		},
		{
			Reference:  "dbcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9",
			Equivalent: "docker.io/library/dbcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9",
			Digests: []digest.Digest{
				digest.Digest("sha256:abcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9c"),
			},
		},
		{
			Reference: "dbcc1c",
			Expected:  digestReference("sha256:dbcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9c"),
			Digests: []digest.Digest{
				digest.Digest("sha256:dbcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9c"),
				digest.Digest("sha256:abcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9c"),
			},
		},
		{
			Reference:  "dbcc1",
			Equivalent: "docker.io/library/dbcc1",
			Digests: []digest.Digest{
				digest.Digest("sha256:dbcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9c"),
				digest.Digest("sha256:abcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9c"),
			},
		},
		{
			Reference:  "dbcc1c",
			Equivalent: "docker.io/library/dbcc1c",
			Digests: []digest.Digest{
				digest.Digest("sha256:abcc1c35ac38df41fd2f5e4130b32ffdb93ebae8b3dbe638c23575912276fc9c"),
			},
		},
	}

	for _, tcase := range tcases {
		var ref Reference
		var err error
		if len(tcase.Digests) == 0 {
			ref, err = ParseAnyReference(tcase.Reference)
		} else {
			ds := digestset.NewSet()
			for _, dgst := range tcase.Digests {
				if err := ds.Add(dgst); err != nil {
					t.Fatalf("Error adding digest %s: %v", dgst.String(), err)
				}
			}
			ref, err = ParseAnyReferenceWithSet(tcase.Reference, ds)
		}
		if err != nil {
			t.Fatalf("Error parsing reference %s: %v", tcase.Reference, err)
		}

		expected := tcase.Expected
		if expected == nil {
			expected, err = Parse(tcase.Equivalent)
			if err != nil {
				t.Fatalf("Error parsing reference %s: %v", tcase.Equivalent, err)
			}
		}
		if !equalReference(ref, expected) {
			t.Errorf("Unexpected reference %#v, expected %#v", ref, expected)
		}
	}
}
