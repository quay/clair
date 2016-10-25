package distribution

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/reference"
	"github.com/docker/docker/registry"
	"github.com/docker/docker/utils"
	"github.com/docker/engine-api/types"
	registrytypes "github.com/docker/engine-api/types/registry"
	"golang.org/x/net/context"
)

const secretRegistryToken = "mysecrettoken"

type tokenPassThruHandler struct {
	reached       bool
	gotToken      bool
	shouldSend401 func(url string) bool
}

func (h *tokenPassThruHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.reached = true
	if strings.Contains(r.Header.Get("Authorization"), secretRegistryToken) {
		logrus.Debug("Detected registry token in auth header")
		h.gotToken = true
	}
	if h.shouldSend401 == nil || h.shouldSend401(r.RequestURI) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="foorealm"`)
		w.WriteHeader(401)
	}
}

func testTokenPassThru(t *testing.T, ts *httptest.Server) {
	tmp, err := utils.TestDirectory("")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	uri, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("could not parse url from test server: %v", err)
	}

	endpoint := registry.APIEndpoint{
		Mirror:       false,
		URL:          uri,
		Version:      2,
		Official:     false,
		TrimHostname: false,
		TLSConfig:    nil,
		//VersionHeader: "verheader",
	}
	n, _ := reference.ParseNamed("testremotename")
	repoInfo := &registry.RepositoryInfo{
		Named: n,
		Index: &registrytypes.IndexInfo{
			Name:     "testrepo",
			Mirrors:  nil,
			Secure:   false,
			Official: false,
		},
		Official: false,
	}
	imagePullConfig := &ImagePullConfig{
		MetaHeaders: http.Header{},
		AuthConfig: &types.AuthConfig{
			RegistryToken: secretRegistryToken,
		},
	}
	puller, err := newPuller(endpoint, repoInfo, imagePullConfig)
	if err != nil {
		t.Fatal(err)
	}
	p := puller.(*v2Puller)
	ctx := context.Background()
	p.repo, _, err = NewV2Repository(ctx, p.repoInfo, p.endpoint, p.config.MetaHeaders, p.config.AuthConfig, "pull")
	if err != nil {
		t.Fatal(err)
	}

	logrus.Debug("About to pull")
	// We expect it to fail, since we haven't mock'd the full registry exchange in our handler above
	tag, _ := reference.WithTag(n, "tag_goes_here")
	_ = p.pullV2Repository(ctx, tag)
}

func TestTokenPassThru(t *testing.T) {
	handler := &tokenPassThruHandler{shouldSend401: func(url string) bool { return url == "/v2/" }}
	ts := httptest.NewServer(handler)
	defer ts.Close()

	testTokenPassThru(t, ts)

	if !handler.reached {
		t.Fatal("Handler not reached")
	}
	if !handler.gotToken {
		t.Fatal("Failed to receive registry token")
	}
}

func TestTokenPassThruDifferentHost(t *testing.T) {
	handler := new(tokenPassThruHandler)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	tsredirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI == "/v2/" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="foorealm"`)
			w.WriteHeader(401)
			return
		}
		http.Redirect(w, r, ts.URL+r.URL.Path, http.StatusMovedPermanently)
	}))
	defer tsredirect.Close()

	testTokenPassThru(t, tsredirect)

	if !handler.reached {
		t.Fatal("Handler not reached")
	}
	if handler.gotToken {
		t.Fatal("Redirect should not forward Authorization header to another host")
	}
}
