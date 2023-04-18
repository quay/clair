package compress

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
)

var (
	setupOnce   sync.Once
	setupErr    error
	testhandler http.Handler
	body        []byte
)

func setupHandler(t *testing.T) {
	const writeSz = 1024 * 1024
	setupOnce.Do(func() {
		body = make([]byte, writeSz)
		if _, err := io.ReadFull(rand.Reader, body); err != nil {
			setupErr = err
			return
		}
		testhandler = Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rd := bytes.NewReader(body)
			if _, err := io.Copy(w, rd); err != nil {
				panic(err)
			}
		}))
	})
	if setupErr != nil {
		t.Fatal(setupErr)
	}
}

type mkFunc func(io.Reader) (io.ReadCloser, error)

func testencoding(t *testing.T, enc string, status int, mk mkFunc) {
	t.Helper()
	setupHandler(t)
	srv := httptest.NewServer(testhandler)
	t.Cleanup(srv.Close)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+`/`+enc, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("accept-encoding", enc)
	t.Logf("Accept-Encoding: %q", enc)
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := res.Body.Close(); err != nil {
			t.Error(err)
		}
	})
	if ce := res.Header.Get("content-encoding"); ce != "" {
		t.Logf("Content-Encoding: %q", ce)
	}
	if ae := res.Header.Get("accept-encoding"); ae != "" {
		t.Logf("Accept-Encoding: %q", ae)
	}
	t.Logf("got: %s, want: %d %s", res.Status, status, http.StatusText(status))
	if got, want := res.StatusCode, status; got != want {
		t.Fail()
	}
	if status != http.StatusOK {
		t.Log("non-200 status expected, skipping body check")
		return
	}
	z, err := mk(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := z.Close(); err != nil {
			t.Error(err)
		}
	})
	var got bytes.Buffer
	if _, err := got.ReadFrom(z); err != nil {
		t.Error(err)
	}
	if !bytes.Equal(got.Bytes(), body) {
		t.Error("body not correct")
	}
	t.Log("body OK")
}

func TestCompressor(t *testing.T) {
	tt := []struct {
		Name   string
		Enc    string
		Mk     mkFunc
		Status int
	}{
		{
			Name:   "Empty",
			Enc:    ``,
			Mk:     func(r io.Reader) (io.ReadCloser, error) { return io.NopCloser(r), nil },
			Status: http.StatusOK,
		},
		{
			Name:   "Identity",
			Enc:    `identity`,
			Mk:     func(r io.Reader) (io.ReadCloser, error) { return io.NopCloser(r), nil },
			Status: http.StatusOK,
		},
		{
			Name:   "Gzip",
			Enc:    `gzip`,
			Mk:     func(r io.Reader) (io.ReadCloser, error) { return gzip.NewReader(r) },
			Status: http.StatusOK,
		},
		{
			Name:   "Deflate",
			Enc:    `deflate`,
			Mk:     func(r io.Reader) (io.ReadCloser, error) { return flate.NewReader(r), nil },
			Status: http.StatusOK,
		},
		{
			Name: "Zstd",
			Enc:  `zstd`,
			Mk: func(r io.Reader) (io.ReadCloser, error) {
				z, err := zstd.NewReader(r)
				if err != nil {
					return nil, err
				}
				return z.IOReadCloser(), nil
			},
			Status: http.StatusOK,
		},
		// The examples in the RFC:
		{
			Name:   "RFC9110",
			Enc:    `compress, gzip`,
			Mk:     func(r io.Reader) (io.ReadCloser, error) { return gzip.NewReader(r) },
			Status: http.StatusOK,
		},
		{
			Name:   "RFC9110",
			Enc:    ``,
			Mk:     func(r io.Reader) (io.ReadCloser, error) { return io.NopCloser(r), nil },
			Status: http.StatusOK,
		},
		{
			Name:   "RFC9110",
			Enc:    `*`,
			Mk:     func(r io.Reader) (io.ReadCloser, error) { return gzip.NewReader(r) },
			Status: http.StatusOK,
		},
		{
			Name:   "RFC9110",
			Enc:    `compress;q=0.5, gzip;q=1.0`,
			Mk:     func(r io.Reader) (io.ReadCloser, error) { return gzip.NewReader(r) },
			Status: http.StatusOK,
		},
		{
			Name:   "RFC9110",
			Enc:    `gzip;q=1.0, identity; q=0.5, *;q=0`,
			Mk:     func(r io.Reader) (io.ReadCloser, error) { return gzip.NewReader(r) },
			Status: http.StatusOK,
		},
		{
			Name:   "OldGzip",
			Enc:    `x-gzip, *;q=0`,
			Mk:     func(r io.Reader) (io.ReadCloser, error) { return gzip.NewReader(r) },
			Status: http.StatusOK,
		},
		{
			Name:   "Unacceptable",
			Enc:    `test, *;q=0`,
			Status: http.StatusUnsupportedMediaType,
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			testencoding(t, tc.Enc, tc.Status, tc.Mk)
		})
	}
}
