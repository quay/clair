package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
)

// TestImportArg checks that the import subcommand's magic URL handling is
// correct.
func TestImportArg(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "http")
	}))
	defer srv.Close()

	tt := []struct {
		In  string
		Err bool
		Ok  func(*testing.T, io.ReadCloser)
	}{
		{
			In: "import_test.go",
			Ok: func(t *testing.T, in io.ReadCloser) {
				if got, want := reflect.TypeOf(in), reflect.TypeOf(&os.File{}); got != want {
					t.Errorf("got: %T, want: %T", got, want)
				}
			},
		},
		{
			In: "./import_test.go",
			Ok: func(t *testing.T, in io.ReadCloser) {
				if got, want := reflect.TypeOf(in), reflect.TypeOf(&os.File{}); got != want {
					t.Errorf("got: %T, want: %T", got, want)
				}
			},
		},
		{
			In: srv.URL,
			Ok: func(t *testing.T, rc io.ReadCloser) {
				b := bytes.Buffer{}
				if _, err := b.ReadFrom(rc); err != nil {
					t.Errorf("read error: %v", err)
				}
				if got, want := b.String(), "http"; got != want {
					t.Errorf("got: %q, want: %q", got, want)
				}
			},
		},
		{
			In:  "invalid",
			Err: true,
			Ok:  func(*testing.T, io.ReadCloser) {},
		},
	}

	ctx := context.Background()
	for _, tc := range tt {
		rc, err := openInput(ctx, srv.Client(), tc.In)
		t.Logf("%q: %T; %v", tc.In, rc, err)
		if (err != nil) && !tc.Err {
			t.Error()
		}
		tc.Ok(t, rc)
		if rc != nil {
			rc.Close()
		}
	}
}
