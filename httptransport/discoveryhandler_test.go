package httptransport

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/quay/zlog"
)

func TestDiscoveryEndpoint(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	h := DiscoveryHandler()

	r := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/openapi/v1", nil).WithContext(ctx)
	req.Header.Set("Accept", "application/yaml, application/json; q=0.4, application/vnd.oai.openapi+json; q=1.0")
	h.ServeHTTP(r, req)

	resp := r.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status code: %v want status code: %v", resp.StatusCode, http.StatusOK)
	}
	if got, want := resp.Header.Get("content-type"), "application/vnd.oai.openapi+json"; got != want {
		t.Errorf("got: %q, want: %q", got, want)
	}

	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to ready response body: %v", err)
	}

	m := map[string]interface{}{}
	err = json.Unmarshal(buf, &m)
	if err != nil {
		t.Fatalf("failed to json parse returned bytes: %v", err)
	}

	if _, ok := m["openapi"]; !ok {
		t.Fatalf("returned json did not container openapi key at the root")
	}
	t.Logf("openapi verion: %v", m["openapi"])
}

func TestDiscoveryFailure(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	h := DiscoveryHandler()

	r := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/openapi/v1", nil).WithContext(ctx)
	req.Header.Set("Accept", "application/yaml")
	h.ServeHTTP(r, req)

	resp := r.Result()
	if got, want := resp.StatusCode, http.StatusUnsupportedMediaType; got != want {
		t.Fatalf("got status code: %v want status code: %v", got, want)
	}
}

func TestEmbedding(t *testing.T) {
	d := t.TempDir()
	var buf bytes.Buffer
	cmd := exec.Command("go", "run", "openapigen.go", "-in", "../openapi.yaml", "-out", d)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	t.Log(cmd.Args)
	if err := cmd.Run(); err != nil {
		t.Error(err)
		t.Error(buf.String())
	}

	for _, n := range []string{
		"openapi.json", "openapi.etag"} {
		new, err := os.ReadFile(filepath.Join(d, n))
		if err != nil {
			t.Error(err)
			continue
		}
		old, err := os.ReadFile(n)
		if err != nil {
			t.Error(err)
			continue
		}
		if got, want := string(new), string(old); !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want, cmpopts.AcyclicTransformer("normalizeWhitespace", func(s string) []string { return strings.Split(s, "\n") })))
			t.Log("\n\tYou probably edited the openapi.yaml and forgot to run `go generate` here.")
		}
	}
}
