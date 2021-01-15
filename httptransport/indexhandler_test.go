package httptransport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/opencontainers/go-digest"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/quay/claircore"
)

func TestNativeFromOCI(t *testing.T) {
	t.Parallel()

	var cmpOpts = cmp.Options{
		cmp.Comparer(func(a, b claircore.Digest) bool { return a.String() == b.String() }),
		cmpopts.IgnoreUnexported(claircore.Layer{}),
	}
	type testcase struct {
		Name string
		Want claircore.Manifest
		In   oci.Manifest
		Err  bool
	}
	Run := func(tc *testcase) func(*testing.T) {
		return func(t *testing.T) {
			var got claircore.Manifest

			err := nativeFromOCI(&got, &tc.In)
			if (err != nil) != tc.Err {
				t.Errorf("unexpected error: %v", err)
			}

			if got, want := &got, &tc.Want; !cmp.Equal(got, want, cmpOpts) {
				t.Error(cmp.Diff(got, want, cmpOpts))
			}
		}
	}

	tt := []testcase{
		{
			Name: "EmptyDigest",
			In:   oci.Manifest{},
			Err:  true,
		},
		{
			Name: "BadDigest",
			In: oci.Manifest{
				Config: oci.Descriptor{
					Digest: digest.Digest("xxx:yyy"),
				},
			},
			Err: true,
		},
		{
			Name: "BadURLs",
			In: oci.Manifest{
				Config: oci.Descriptor{
					Digest: digest.FromString("good manifest"),
				},
				Layers: []oci.Descriptor{
					{URLs: nil},
				},
			},
			Want: claircore.Manifest{
				Hash: claircore.MustParseDigest("sha256:a3114909b7f9d6c4a680e04c3f6eacaeb80c4d9d8d802f81e9b9cf0a29d26e19"),
			},
			Err: true,
		},
		{
			Name: "BadMediaType",
			In: oci.Manifest{
				Config: oci.Descriptor{
					Digest: digest.FromString("good manifest"),
				},
				Layers: []oci.Descriptor{
					{
						MediaType: `fake/media-type`,
						URLs:      []string{"http://localhost/real/layer"},
					},
				},
			},
			Want: claircore.Manifest{
				Hash: claircore.MustParseDigest("sha256:a3114909b7f9d6c4a680e04c3f6eacaeb80c4d9d8d802f81e9b9cf0a29d26e19"),
			},
			Err: true,
		},
		{
			Name: "BadLayerDigest",
			In: oci.Manifest{
				Config: oci.Descriptor{
					Digest: digest.FromString("good manifest"),
				},
				Layers: []oci.Descriptor{
					{
						Digest:    digest.Digest("xxx:yyy"),
						MediaType: oci.MediaTypeImageLayer,
						URLs:      []string{"http://localhost/real/layer"},
					},
				},
			},
			Want: claircore.Manifest{
				Hash: claircore.MustParseDigest("sha256:a3114909b7f9d6c4a680e04c3f6eacaeb80c4d9d8d802f81e9b9cf0a29d26e19"),
			},
			Err: true,
		},
		{
			Name: "OK",
			Want: claircore.Manifest{
				Hash: claircore.MustParseDigest("sha256:a3114909b7f9d6c4a680e04c3f6eacaeb80c4d9d8d802f81e9b9cf0a29d26e19"),
				Layers: []*claircore.Layer{
					{
						Hash: claircore.MustParseDigest("sha256:ba54d2c66022c637137ad0896ba5fb790847755be51b08bc472ffab5fdd76b1b"),
						URI:  "http://localhost/real/layer",
					},
				},
			},
			In: oci.Manifest{
				Config: oci.Descriptor{
					Digest: digest.FromString("good manifest"),
				},
				Layers: []oci.Descriptor{
					{
						Digest:    digest.FromString("cool layer"),
						MediaType: oci.MediaTypeImageLayer,
						URLs:      []string{"http://localhost/real/layer"},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, Run(&tc))
	}
}

func TestDecodeManifest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	type testcase struct {
		Name string
		Want claircore.Manifest
		In   *http.Request
		Err  bool
	}
	Run := func(tc *testcase) func(*testing.T) {
		return func(t *testing.T) {
			got, err := decodeManifest(ctx, tc.In)
			if err != nil {
				t.Log(err)
			}
			if (err != nil) != tc.Err {
				t.Errorf("unexpected error: %v", err)
			}
			_ = got
		}
	}

	const (
		goodOCI = `{
		"mediaType":"` + oci.MediaTypeImageManifest + `",
		"config":{"digest":"sha256:a3114909b7f9d6c4a680e04c3f6eacaeb80c4d9d8d802f81e9b9cf0a29d26e19"},
		"layers":[{
			"mediaType":"` + oci.MediaTypeImageLayer + `",
			"digest":"sha256:a3114909b7f9d6c4a680e04c3f6eacaeb80c4d9d8d802f81e9b9cf0a29d26e19",
			"urls":["http://example.com/layer"]
		}]}`
		errorOCI = `{
		"mediaType":"` + oci.MediaTypeImageManifest + `",
		"config":{"digest":"sha256:a3114909b7f9d6c4a680e04c3f6eacaeb80c4d9d8d802f81e9b9cf0a29d26e19"},
		"layers":[{
			"mediaType":"` + oci.MediaTypeImageLayer + `",
			"digest":"sha256:a3114909b7f9d6c4a680e04c3f6eacaeb80c4d9d8d802f81e9b9cf0a29d26e19"
		}]}`
	)
	tt := []testcase{
		{
			Name: "NoHeaders",
			In:   httptest.NewRequest("", "/", strings.NewReader(`{}`)),
		},
		{
			Name: "BadContentType",
			In:   httptest.NewRequest("", "/", strings.NewReader(`{}`)),
			Err:  true,
		},
		{
			Name: "Default",
			In:   httptest.NewRequest("", "/", strings.NewReader(`{}`)),
		},
		{
			Name: "Default+Error",
			In:   httptest.NewRequest("", "/", strings.NewReader(`""`)),
			Err:  true,
		},
		{
			Name: "Claircore",
			In:   httptest.NewRequest("", "/", strings.NewReader(`{}`)),
		},
		{
			Name: "OCIManifest",
			In:   httptest.NewRequest("", "/", strings.NewReader(goodOCI)),
		},
		{
			Name: "OCIManifest+DecodeError",
			In:   httptest.NewRequest("", "/", strings.NewReader(`""`)),
			Err:  true,
		},
		{
			Name: "OCIManifest+TranslateError",
			In:   httptest.NewRequest("", "/", strings.NewReader(errorOCI)),
			Err:  true,
		},
	}
	// Adjust headers
	for _, tc := range tt {
		switch tc.Name {
		case "NoHeaders":
		case "BadContentType":
			tc.In.Header.Set(`content-type`, `text/plain; charset=UTF-8`)
		case "OCIManifest", "OCIManifest+DecodeError", "OCIManifest+TranslateError":
			tc.In.Header.Set(`content-type`, oci.MediaTypeImageManifest)
		case "Claircore":
			tc.In.Header.Set(`content-type`, `application/json; charset=UTF-8`)
		default:
			tc.In.Header.Set(`content-type`, `application/json; charset=UTF-8`)
		}
	}

	for _, tc := range tt {
		t.Run(tc.Name, Run(&tc))
	}
}
