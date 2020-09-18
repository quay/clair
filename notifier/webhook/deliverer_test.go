package webhook

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/quay/claircore/test/log"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/quay/clair/v4/notifier"
	"github.com/quay/clair/v4/notifier/keymanager"
)

var (
	callback = "http://clair-notifier/notifier/api/v1/notification"
	noteID   = uuid.New()
)

// TestDeliverer is a parallel test harness
func TestDeliverer(t *testing.T) {
	t.Run("TestSign", testSign)
	t.Run("TestDeliverer", testDeliverer)
}

// testSign confirms the deliverer correctly signs a webhook
func testSign(t *testing.T) {
	t.Parallel()

	target, _ := url.Parse("https://example.com/endpoint")
	d := Deliverer{
		conf: Config{
			target: target,
		},
	}
	kp := (genKeyPair(t, 1))[0]
	req, err := http.NewRequest(http.MethodGet, "", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	ctx, done := log.TestLogger(context.Background(), t)
	defer done()
	err = d.sign(ctx, req, kp)
	if err != nil {
		t.Fatalf("failed to sign request: %v", err)
	}

	token := req.Header.Get("Authorization")
	if !strings.HasPrefix(token, "Bearer") {
		t.Fatalf("no Bearer prefix on token")
	}
	token = strings.TrimPrefix(token, "Bearer ")

	j, err := jwt.ParseSigned(token)
	if err != nil {
		t.Errorf("failed to parse jwt: %v", err)
	}
	headers := j.Headers[0]
	if headers.KeyID != kp.ID.String() {
		t.Fatalf("got: %v want: %v", headers.KeyID, kp.ID.String())
	}

	var claims jwt.Claims
	err = j.Claims(kp.Public, &claims)
	if err != nil {
		t.Errorf("failed to deserialize claims with public key: %v", err)
	}

	if claims.Issuer != "notifier" {
		t.Errorf("got: %v want: %v", claims.Issuer, "notifier")
	}
	if claims.Audience[0] != target.String() {
		t.Errorf("got: %v want: %v", claims.Audience, target.String())
	}
	if claims.Subject != target.Hostname() {
		t.Errorf("got: %v want: %v", claims.Subject, target.Hostname())
	}

	object, err := jose.ParseSigned(token)
	if err != nil {
		t.Fatalf("unable to parse signed token")
	}

	_, err = object.Verify(kp.Public)
	if err != nil {
		t.Fatalf("token failed public key validation: %v", err)
	}
}

// testDeliverer confirms the deliverer correctly sends the webhook
// datas structure to the configured target.
func testDeliverer(t *testing.T) {
	t.Parallel()

	var whResult struct {
		sync.Mutex
		cb notifier.Callback
	}
	var server *httptest.Server = httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			var cb notifier.Callback
			err := json.NewDecoder(r.Body).Decode(&cb)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			whResult.Lock()
			whResult.cb = cb
			whResult.Unlock()
			return
		},
	))
	ctx, done := log.TestLogger(context.Background(), t)
	defer done()
	conf := Config{
		Callback: callback,
		Target:   server.URL,
	}
	var err error
	conf, err = conf.Validate()
	if err != nil {
		t.Fatalf("failed to validate webhook config: %v", err)
	}

	d, err := New(conf, nil, nil)
	if err != nil {
		t.Fatalf("failed to create new webhook deliverer: %v", err)
	}
	err = d.Deliver(ctx, noteID)
	if err != nil {
		t.Fatalf("got: %v, wanted: nil", err)
	}

	whResult.Lock()
	wh := whResult.cb
	whResult.Unlock()

	if !cmp.Equal(wh.NotificationID, noteID) {
		t.Fatalf("got: %v, wanted: %v", wh.NotificationID, noteID)
	}

	cbURL, err := url.Parse(callback)
	if err != nil {
		t.Fatalf("failed to parse callback url: %v", err)
	}
	cbURL.Path = path.Join(cbURL.Path, noteID.String())

	if !cmp.Equal(wh.Callback, *cbURL) {
		t.Fatalf("got: %v, wanted: %v", wh.Callback, cbURL)
	}
}

func genKeyPair(t *testing.T, n int) (kps []keymanager.KeyPair) {
	reader := rand.Reader
	bitSize := 2048
	for i := 0; i < n; i++ {
		key, err := rsa.GenerateKey(reader, bitSize)
		if err != nil {
			t.Fatalf("failed to generate test key pair: %v", err)
		}

		pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatalf("failed to marshal public key to PKIX")
		}
		id := uuid.New()

		kps = append(kps, keymanager.KeyPair{
			ID:      id,
			Private: key,
			Public:  &key.PublicKey,
			Der:     pub,
		})
	}
	return kps
}
