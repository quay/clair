package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/quay/claircore/libvuln/driver"

	"github.com/quay/clair/v4/httptransport"
	"github.com/quay/clair/v4/httptransport/client"
)

// TestDiffer puts the Differ methods of the client through its paces.
func TestDiffer(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()

	t.Run("OK", func(t *testing.T) {
		t.Run("Delete", func(t *testing.T) {
			t.Parallel()
			// Generate a set of refs.
			refs := make([]uuid.UUID, 10)
			expected := make(map[string]struct{}, 10)
			for i := range refs {
				id := uuid.New()
				refs[i] = id
				expected[id.String()] = struct{}{}
			}

			// Spin up a server that mocks a delete call.
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				if !strings.HasPrefix(r.URL.Path, httptransport.UpdatesAPIPath) {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				got := path.Base(r.URL.Path)
				t.Logf("got: %s", got)
				if _, ok := expected[got]; !ok {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			// Create a client.
			c, err := client.NewHTTP(ctx, client.WithAddr(srv.URL))
			if err != nil {
				t.Fatal(err)
			}

			// Do the call.
			if err := c.DeleteUpdateOperations(ctx, refs...); err != nil {
				t.Error(err)
			}
		})

		t.Run("Latest", func(t *testing.T) {
			t.Parallel()
			// Generate a set of names and refs.
			want := make(map[string]uuid.UUID)
			for i := 0; i < 10; i++ {
				want[strconv.Itoa(i)] = uuid.New()
			}
			validator := `"validator"`

			// Spin up a server that mocks a latest call.
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				if !strings.HasPrefix(r.URL.Path, httptransport.UpdatesAPIPath) {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if v := r.Header.Get("If-None-Match"); v != "" && v == validator {
					w.WriteHeader(http.StatusNotModified)
					return
				}
				w.Header().Set("etag", validator)

				if err := json.NewEncoder(w).Encode(want); err != nil {
					t.Error(err)
				}
			}))
			defer srv.Close()

			// Create a client.
			c, err := client.NewHTTP(ctx, client.WithAddr(srv.URL))
			if err != nil {
				t.Fatal(err)
			}

			t.Run("Initial", func(t *testing.T) {
				// Do the call.
				got, err := c.LatestUpdateOperations(ctx)
				if err != nil {
					t.Error(err)
				}
				if !cmp.Equal(got, want) {
					t.Error(cmp.Diff(got, want))
				}
			})
			t.Run("Second", func(t *testing.T) {
				// Do the call.
				_, err := c.LatestUpdateOperations(ctx)
				if got, want := err, client.ErrUnchanged; !errors.Is(got, want) {
					t.Errorf("got: %v, want: %v", got, want)
				}
			})
		})

		t.Run("Diff", func(t *testing.T) {
			t.Parallel()
			// Create two refs and a delta between them.
			prev, cur := uuid.New(), uuid.New()
			want := &driver.UpdateDiff{
				A:       driver.UpdateOperation{Ref: prev},
				B:       driver.UpdateOperation{Ref: cur},
				Added:   nil,
				Removed: nil,
			}

			// Spin up a server that mocks the diff call.
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}

				prevStr, curStr := r.FormValue("prev"), r.FormValue("cur")
				if got, want := prevStr, prev.String(); got != want {
					t.Errorf("got: %q, want: %q", got, want)
				}
				if got, want := curStr, cur.String(); got != want {
					t.Errorf("got: %q, want: %q", got, want)
				}
				if t.Failed() {
					w.WriteHeader(http.StatusBadRequest)
					return
				}

				if err := json.NewEncoder(w).Encode(want); err != nil {
					t.Error(err)
				}
			}))
			defer srv.Close()

			// Create a client.
			c, err := client.NewHTTP(ctx, client.WithAddr(srv.URL))
			if err != nil {
				t.Fatal(err)
			}

			// Do the call.
			got, err := c.UpdateDiff(ctx, prev, cur)
			if err != nil {
				t.Error(err)
			}
			if !cmp.Equal(got, want) {
				t.Error(cmp.Diff(got, want))
			}
		})
	})
}
