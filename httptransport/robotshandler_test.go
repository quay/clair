package httptransport

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestRobotsTXT(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	w := httptest.NewRecorder()
	robotsHandler.ServeHTTP(w, r)
	res, err := httputil.DumpResponse(w.Result(), false)
	if err != nil {
		t.Error(err)
	}
	t.Logf("response:\n%s", string(res))

	if got, want := w.Body.Bytes(), []byte(robotstxt); !bytes.Equal(got, want) {
		t.Error(cmp.Diff(string(got), string(want)))
	}
}
