package httputil

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResponseRecorder(t *testing.T) {
	t.Run("OK", func(t *testing.T) {
		var status int
		var length int64

		rec := httptest.NewRecorder()
		w := ResponseRecorder(&status, &length, rec)

		sz := 512
		if n, err := w.Write(make([]byte, sz)); err != nil || n != sz {
			t.Errorf("unexpected Write return: (%v, %v)", n, err)
		}
		t.Logf("wrote %d bytes, status %q", length, http.StatusText(status))
		if got, want := status, http.StatusOK; got != want {
			t.Errorf("bad status; got: %d, want: %d", got, want)
		}
		if got, want := length, int64(sz); got != want {
			t.Errorf("bad length; got: %d, want: %d", got, want)
		}
	})

	t.Run("Error", func(t *testing.T) {
		var status int
		var length int64
		sc := http.StatusInternalServerError

		rec := httptest.NewRecorder()
		w := ResponseRecorder(&status, &length, rec)

		sz := 512
		w.WriteHeader(sc)
		if n, err := w.Write(make([]byte, sz)); err != nil || n != sz {
			t.Errorf("unexpected Write return: (%v, %v)", n, err)
		}
		t.Logf("wrote %d bytes, status %q", length, http.StatusText(status))
		if got, want := status, sc; got != want {
			t.Errorf("bad status; got: %d, want: %d", got, want)
		}
		if got, want := length, int64(sz); got != want {
			t.Errorf("bad length; got: %d, want: %d", got, want)
		}
	})
}
