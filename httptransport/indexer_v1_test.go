package httptransport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/opencontainers/go-digest"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/quay/claircore"
	"github.com/quay/zlog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"

	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/internal/codec"
)

func TestIndexerV1(t *testing.T) {
	ctx := context.Background()
	ctx = zlog.Test(ctx, t)

	digest := claircore.MustParseDigest("sha256:0000000000000000000000000000000000000000000000000000000000000000")
	i := &indexer.Mock{
		State_: func(ctx context.Context) (string, error) {
			return `deadbeef`, nil
		},
		DeleteManifests_: func(_ context.Context, ds ...claircore.Digest) ([]claircore.Digest, error) {
			for _, d := range ds {
				if got, want := d.String(), digest.String(); got != want {
					return nil, fmt.Errorf("unexpected digest: %v", d)
				}
			}
			return ds, nil
		},
		Index_: func(ctx context.Context, m *claircore.Manifest) (*claircore.IndexReport, error) {
			return new(claircore.IndexReport), nil
		},
		IndexReport_: func(_ context.Context, d claircore.Digest) (*claircore.IndexReport, bool, error) {
			if got, want := d.String(), digest.String(); got != want {
				return nil, false, fmt.Errorf("unexpected digest: %v", d)
			}
			return new(claircore.IndexReport), true, nil
		},
		AffectedManifests_: func(_ context.Context, _ []claircore.Vulnerability) (*claircore.AffectedManifests, error) {
			return new(claircore.AffectedManifests), nil
		},
	}

	v1, err := NewIndexerV1(ctx, "", i, otelhttp.WithTracerProvider(trace.NewNoopTracerProvider()))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(v1)
	srv.Config.BaseContext = func(_ net.Listener) context.Context { return ctx }
	srv.Start()
	defer srv.Close()

	t.Run("State", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		const path = `/index_state`
		t.Run("GET", func(t *testing.T) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, want := res.StatusCode, http.StatusOK
			t.Logf("got: %d, want: %d", got, want)
			if got != want {
				t.Error()
			}
		})
	})
	t.Run("Report", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		const path = `/index_report`
		t.Run("POST", func(t *testing.T) {
			const body = `{"hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000",` +
				`"layers":[{}]}`
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+path, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, want := res.StatusCode, http.StatusCreated
			t.Logf("got: %d, want: %d", got, want)
			if got != want {
				t.Error()
			}
		})
		t.Run("DELETE", func(t *testing.T) {
			const body = `["sha256:0000000000000000000000000000000000000000000000000000000000000000"]`
			req, err := http.NewRequestWithContext(ctx, http.MethodDelete, srv.URL+path, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			var buf bytes.Buffer
			got, want := res.StatusCode, http.StatusOK
			t.Logf("got: %d, want: %d", got, want)
			if got != want {
				t.Error()
			}
			if _, err := io.Copy(&buf, res.Body); err != nil {
				t.Error(err)
			}
			// Should get back what we put in, so this is a little hack.
			if got, want := buf.String(), body; got != want {
				t.Errorf("got: %q, want: %q", got, want)
			}
		})
		t.Run("GET", func(t *testing.T) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, want := res.StatusCode, http.StatusMethodNotAllowed
			t.Logf("got: %d, want: %d", got, want)
			if got != want {
				t.Error()
			}
		})
	})
	t.Run("ReportOne", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		const path = `/index_report/sha256:0000000000000000000000000000000000000000000000000000000000000000`
		t.Run("DELETE", func(t *testing.T) {
			req, err := http.NewRequestWithContext(ctx, http.MethodDelete, srv.URL+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, want := res.StatusCode, http.StatusNoContent
			t.Logf("got: %d, want: %d", got, want)
			if got != want {
				t.Error()
			}
		})
		t.Run("GET", func(t *testing.T) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, want := res.StatusCode, http.StatusOK
			t.Logf("got: %d, want: %d", got, want)
			if got != want {
				t.Error()
			}
		})
	})
	t.Run("AffectedManifests", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		const path = `/internal/affected_manifest/`
		t.Run("POST", func(t *testing.T) {
			const body = `{"vulnerabilities":[]}`
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+path, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, want := res.StatusCode, http.StatusOK
			t.Logf("got: %d, want: %d", got, want)
			if got != want {
				t.Error()
			}
		})
	})
}

func TestNativeFromOCI(t *testing.T) {
	t.Parallel()

	cmpOpts := cmp.Options{
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
		In   *http.Request
		Want claircore.Manifest
		Err  bool
	}
	Run := func(tc *testcase) func(*testing.T) {
		return func(t *testing.T) {
			dec := codec.GetDecoder(tc.In.Body)
			defer codec.PutDecoder(dec)
			got, err := decodeManifest(ctx, tc.In, dec)
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
