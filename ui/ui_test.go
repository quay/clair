package ui_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/quay/clair/v4/ui"
)

func TestIndex(t *testing.T) {
	h, err := ui.New()
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	rec.Body = new(bytes.Buffer)

	h.ServeHTTP(rec, req)
	res := rec.Result()

	t.Logf("%+#q", rec.Body.String())

	if res.StatusCode != http.StatusOK {
		t.Fail()
	}
}
