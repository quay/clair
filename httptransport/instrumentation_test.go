package httptransport

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/quay/zlog"
)

func TestMetric(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	want := strings.NewReader(`
# HELP clair_http_test_request_total A total count of http requests for the given path
# TYPE clair_http_test_request_total counter
clair_http_test_request_total{code="200",handler="ok",method="get"} 1
clair_http_test_request_total{code="504",handler="err",method="get"} 1
clair_http_test_request_total{code="500",handler="err",method="get"} 1
`)

	reg := prometheus.NewRegistry()
	var wr wrapper
	wr.initRegisterer("test", reg)
	m := http.NewServeMux()
	m.Handle("/ok",
		wr.wrapFunc("ok", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "ok")
		})))
	m.Handle("/err",
		wr.wrapFunc("err", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				panic(err)
			}
			if r.Form.Has("panic") {
				panic("we're just normal men")
			}
			apiError(r.Context(), w, http.StatusGatewayTimeout, "expected error")
		})))

	srv := httptest.NewUnstartedServer(m)
	srv.Config.BaseContext = func(_ net.Listener) context.Context { return ctx }

	// Create a scope for doing the actual requests.
	//
	// Doing this and having the server teardown run synchronously should be
	// enough time to ensure the metrics are actually collected.
	func() {
		srv.Start()
		defer srv.Close()

		c := srv.Client()
		for _, p := range []string{"ok", "err", "err?panic=1"} {
			u := srv.URL + "/" + p
			t.Logf("making request: %q", u)
			res, err := c.Get(u)
			if err != nil {
				t.Error(err)
			}
			t.Logf("got status: %q", res.Status)
		}
	}()

	if err := testutil.GatherAndCompare(reg, want, "clair_http_test_request_total"); err != nil {
		t.Error(err)
	} else {
		t.Log("metrics OK")
	}
}
