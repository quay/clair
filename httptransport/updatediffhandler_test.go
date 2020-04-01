package httptransport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path"
	"testing"

	"github.com/google/uuid"
	"github.com/quay/claircore/libvuln/driver"

	"github.com/quay/clair/v4/matcher"
)

// Differ implements matcher.Differ by calling the func members.
type differ struct {
	delete     func(context.Context, ...uuid.UUID) error
	latest     func(context.Context) (uuid.UUID, error)
	latestOps  func(context.Context) (map[string]uuid.UUID, error)
	updateDiff func(context.Context, uuid.UUID, uuid.UUID) (*driver.UpdateDiff, error)
}

func (d *differ) DeleteUpdateOperations(ctx context.Context, ref ...uuid.UUID) error {
	return d.delete(ctx, ref...)
}
func (d *differ) LatestUpdateOperation(ctx context.Context) (uuid.UUID, error) {
	return d.latest(ctx)
}
func (d *differ) LatestUpdateOperations(ctx context.Context) (map[string]uuid.UUID, error) {
	return d.latestOps(ctx)
}
func (d *differ) UpdateDiff(ctx context.Context, prev, cur uuid.UUID) (*driver.UpdateDiff, error) {
	return d.updateDiff(ctx, prev, cur)
}

var _ matcher.Differ = (*differ)(nil)

// TestUpdateHandler exercises all the call paths of the UpdateDiffHandler.
func TestUpdateHandler(t *testing.T) {
	t.Run("Errors", func(t *testing.T) {
		t.Parallel()
		errExpected := errors.New("expected error")
		h, err := UpdateDiffHandler(&differ{
			delete: func(context.Context, ...uuid.UUID) error {
				return errExpected
			},
			latest: func(context.Context) (uuid.UUID, error) {
				return uuid.Nil, errExpected
			},
			latestOps: func(context.Context) (map[string]uuid.UUID, error) {
				return nil, errExpected
			},
			updateDiff: func(context.Context, uuid.UUID, uuid.UUID) (*driver.UpdateDiff, error) {
				return nil, errExpected
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(h)
		defer srv.Close()
		c := srv.Client()
		srv.URL += UpdatesAPIPath

		t.Run("BadMethod", func(t *testing.T) {
			methodInner := func(t *testing.T, m string, u *url.URL) {
				req, err := http.NewRequest(m, u.String(), nil)
				if err != nil {
					t.Error(err)
					return
				}
				dump, err := httputil.DumpRequestOut(req, false)
				if err != nil {
					t.Error(err)
				}
				t.Logf("%s", dump)
				res, err := c.Do(req)
				if res != nil {
					defer res.Body.Close()
				}
				if err != nil {
					t.Error(err)
					return
				}
				got, want := res.StatusCode, http.StatusMethodNotAllowed
				if got != want {
					t.Errorf("got: %v, want: %v", got, want)
				}
				dump, err = httputil.DumpResponse(res, true)
				if err != nil {
					t.Error(err)
				}
				t.Logf("%s", dump)
			}
			t.Run(".", func(t *testing.T) {
				t.Parallel()
				u, err := url.Parse(srv.URL)
				if err != nil {
					t.Fatal(err)
				}
				u.Path = path.Join(u.Path, "/")
				t.Log(u)
				for _, m := range []string{
					http.MethodConnect,
					http.MethodDelete,
					http.MethodHead,
					http.MethodOptions,
					http.MethodPatch,
					http.MethodPost,
					http.MethodPut,
					http.MethodTrace,
				} {
					methodInner(t, m, u)
				}
			})

			ref := uuid.Nil.String()
			t.Run(ref, func(t *testing.T) {
				t.Parallel()
				u, err := url.Parse(srv.URL)
				if err != nil {
					t.Fatal(err)
				}
				u.Path = path.Join(u.Path, ref)
				t.Log(u)
				for _, m := range []string{
					http.MethodConnect,
					http.MethodGet,
					http.MethodHead,
					http.MethodOptions,
					http.MethodPatch,
					http.MethodPost,
					http.MethodPut,
					http.MethodTrace,
				} {
					methodInner(t, m, u)
				}
			})

			t.Run("diff", func(t *testing.T) {
				t.Parallel()
				u, err := url.Parse(srv.URL)
				if err != nil {
					t.Fatal(err)
				}
				u.Path = path.Join(u.Path, "diff")
				t.Log(u)
				for _, m := range []string{
					http.MethodConnect,
					http.MethodDelete,
					http.MethodHead,
					http.MethodOptions,
					http.MethodPatch,
					http.MethodPost,
					http.MethodPut,
					http.MethodTrace,
				} {
					methodInner(t, m, u)
				}
			})
		})

		t.Run("MalformedRequest", func(t *testing.T) {
			reqInner := func(u string) func(*testing.T) {
				return func(t *testing.T) {
					t.Parallel()
					req, err := http.NewRequest(http.MethodGet, u, nil)
					if err != nil {
						t.Error(err)
						return
					}
					res, err := c.Do(req)
					if res != nil {
						defer res.Body.Close()
					}
					if err != nil {
						t.Error(err)
						return
					}
					got, want := res.StatusCode, http.StatusBadRequest
					if got != want {
						t.Errorf("got: %v, want: %v", got, want)
					}
				}
			}
			u, err := url.Parse(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			u.Path = path.Join(u.Path, "diff")
			t.Log(u)

			t.Run("missing cur", reqInner(u.String()))
			u.RawQuery = (url.Values{"cur": {"12"}}).Encode()
			t.Run("bad cur", reqInner(u.String()))
			u.RawQuery = (url.Values{
				"cur":  {uuid.Nil.String()},
				"prev": {"12"},
			}).Encode()
			t.Run("bad prev", reqInner(u.String()))
		})

		t.Run("Expected", func(t *testing.T) {
			ref := uuid.Nil.String()
			t.Run("404", func(t *testing.T) {
				t.Parallel()
				u, err := url.Parse(srv.URL)
				if err != nil {
					t.Fatal(err)
				}
				u.Path = path.Join(u.Path, "/nonexistent")
				t.Log(u)
				res, err := c.Get(u.String())
				if res != nil {
					t.Log(res.Status)
					defer res.Body.Close()
				}
				if err != nil {
					t.Error(err)
				}
				if got, want := res.StatusCode, http.StatusNotFound; got != want {
					t.Errorf("got: %v, want: %v", got, want)
				}
			})
			t.Run(".", func(t *testing.T) {
				t.Parallel()
				u, err := url.Parse(srv.URL)
				if err != nil {
					t.Fatal(err)
				}
				u.Path = path.Join(u.Path, "/")
				t.Log(u)
				res, err := c.Get(u.String())
				if res != nil {
					t.Log(res.Status)
					defer res.Body.Close()
				}
				if err != nil {
					t.Error(err)
				}
				if got, want := res.StatusCode, http.StatusInternalServerError; got != want {
					t.Errorf("got: %v, want: %v", got, want)
				}
			})
			t.Run("diff", func(t *testing.T) {
				t.Parallel()
				u, err := url.Parse(srv.URL)
				if err != nil {
					t.Fatal(err)
				}
				u.Path = path.Join(u.Path, "diff")
				u.RawQuery = (url.Values{
					"prev": {ref},
					"cur":  {ref},
				}).Encode()
				t.Log(u)
				res, err := c.Get(u.String())
				if res != nil {
					t.Log(res.Status)
					defer res.Body.Close()
				}
				if err != nil {
					t.Error(err)
				}
				if got, want := res.StatusCode, http.StatusInternalServerError; got != want {
					t.Errorf("got: %v, want: %v", got, want)
				}
			})
			t.Run("delete", func(t *testing.T) {
				t.Parallel()
				u, err := url.Parse(srv.URL)
				if err != nil {
					t.Fatal(err)
				}
				u.Path = path.Join(u.Path, ref)
				t.Log(u)
				req, err := http.NewRequest(http.MethodDelete, u.String(), nil)
				if err != nil {
					t.Fatal(err)
				}
				res, err := c.Do(req)
				if res != nil {
					t.Log(res.Status)
					defer res.Body.Close()
				}
				if err != nil {
					t.Error(err)
				}
				if got, want := res.StatusCode, http.StatusInternalServerError; got != want {
					t.Errorf("got: %v, want: %v", got, want)
				}
			})
		})
	})

	t.Run("OK", func(t *testing.T) {
		t.Parallel()
		errUnexpected := errors.New("unexpected error")
		deleteRef, curRef := uuid.New(), uuid.New()
		diff := &driver.UpdateDiff{}
		const updaterKey = `bogus`
		h, err := UpdateDiffHandler(&differ{
			delete: func(_ context.Context, refs ...uuid.UUID) error {
				if len(refs) == 1 && refs[0].String() == deleteRef.String() {
					return nil
				}
				return errUnexpected
			},
			latest: func(context.Context) (uuid.UUID, error) {
				return curRef, nil
			},
			latestOps: func(context.Context) (map[string]uuid.UUID, error) {
				return map[string]uuid.UUID{updaterKey: curRef}, nil
			},
			updateDiff: func(_ context.Context, prev, cur uuid.UUID) (*driver.UpdateDiff, error) {
				if prev.String() == uuid.Nil.String() && cur.String() == curRef.String() {
					return diff, nil
				}
				return nil, errUnexpected
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(h)
		defer srv.Close()
		c := srv.Client()
		srv.URL += UpdatesAPIPath

		t.Run("delete", func(t *testing.T) {
			u, err := url.Parse(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			u.Path = path.Join(u.Path, deleteRef.String())
			t.Log(u)
			req, err := http.NewRequest(http.MethodDelete, u.String(), nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := c.Do(req)
			if res != nil {
				t.Log(res.Status)
				defer res.Body.Close()
			}
			if err != nil {
				t.Error(err)
			}
			if got, want := res.StatusCode, http.StatusOK; got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}
		})
		t.Run("diff", func(t *testing.T) {
			u, err := url.Parse(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			u.Path = path.Join(u.Path, "diff")
			u.RawQuery = (url.Values{"cur": {curRef.String()}}).Encode()
			t.Log(u)
			req, err := http.NewRequest(http.MethodGet, u.String(), nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := c.Do(req)
			if res != nil {
				t.Log(res.Status)
				defer res.Body.Close()
			}
			if err != nil {
				t.Error(err)
			}
			if got, want := res.StatusCode, http.StatusOK; got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}
		})
		t.Run(".", func(t *testing.T) {
			u, err := url.Parse(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			u.Path = path.Join(u.Path, "/")
			t.Log(u)
			req, err := http.NewRequest(http.MethodGet, u.String(), nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := c.Do(req)
			if res != nil {
				t.Log(res.Status)
				defer res.Body.Close()
			}
			if err != nil {
				t.Error(err)
			}
			if got, want := res.StatusCode, http.StatusOK; got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}
			latest := make(map[string]uuid.UUID)
			if err := json.NewDecoder(res.Body).Decode(&latest); err != nil {
				t.Error(err)
			}
			ref, ok := latest[updaterKey]
			if !ok {
				t.Errorf("key %q not present", updaterKey)
			}
			if got, want := ref.String(), curRef.String(); got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}
		})
		t.Run("NotModified", func(t *testing.T) {
			u, err := url.Parse(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			u.Path = path.Join(u.Path, "/")
			t.Log(u)
			req, err := http.NewRequest(http.MethodGet, u.String(), nil)
			if err != nil {
				t.Fatal(err)
			}
			// We happen to know how the validator is constructed, so just
			// cheat and create it.
			req.Header.Add("If-None-Match", fmt.Sprintf(`"%s"`, curRef.String()))
			res, err := c.Do(req)
			if res != nil {
				t.Log(res.Status)
				defer res.Body.Close()
			}
			if err != nil {
				t.Error(err)
			}
			if got, want := res.StatusCode, http.StatusNotModified; got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}
		})
	})
}
