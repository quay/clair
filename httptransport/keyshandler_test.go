package httptransport

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/quay/clair/v4/notifier"
	"github.com/quay/clair/v4/notifier/keymanager"
	jose "gopkg.in/square/go-jose.v2"
)

func TestKeysHandler(t *testing.T) {
	t.Run("Keys", testKeys)
	t.Run("Methods", testKeyByIDHandlerMethods)
}

func testKeys(t *testing.T) {
	t.Parallel()
	kps := genKeyPair(t, 4)
	exp := time.Now().Add(10 * time.Minute)
	keys := []notifier.Key{}
	for _, kp := range kps {
		keys = append(keys, notifier.Key{
			kp.ID, exp, kp.Public,
		})
	}

	mock := &notifier.MockKeyStore{
		Keys_: func(ctx context.Context) ([]notifier.Key, error) {
			return keys, nil
		},
	}

	h := KeysHandler(mock)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("request failed: %v", rr.Code)
	}

	var set jose.JSONWebKeySet
	if err := json.NewDecoder(rr.Body).Decode(&set); err != nil {
		t.Fatalf("failed to deserialize response: %v", err)
	}

	for _, kp := range kps {
		jwks := set.Key(kp.ID.String())
		if len(jwks) != 1 {
			t.Errorf("got: %d want %d", len(jwks), 1)
		}
		pub, ok := jwks[0].Key.(*rsa.PublicKey)
		if !ok {
			t.Errorf("failed to type assert key %v", kp.ID)
		}
		if pub.N.Cmp(kp.Public.N) != 0 {
			t.Errorf("got: %v want %v", pub.N, kp.Public.N)
		}
		if pub.E != kp.Public.E {
			t.Errorf("got: %v want %v", pub.E, kp.Public.E)
		}
	}
}

func genKeyPair(t *testing.T, n int) (kps []keymanager.KeyPair) {
	reader := rand.Reader
	bitSize := 512 // low bitsize for test speed
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

// testKeysHandlerMethods confirms the handler only responds
// to the desired methods.
func testKeyByIDHandlerMethods(t *testing.T) {
	t.Parallel()
	h := KeysHandler(&notifier.MockKeyStore{})
	srv := httptest.NewServer(h)
	defer srv.Close()
	c := srv.Client()

	for _, m := range []string{
		http.MethodConnect,
		http.MethodHead,
		http.MethodOptions,
		http.MethodPatch,
		http.MethodPost,
		http.MethodPut,
		http.MethodTrace,
	} {
		req, err := http.NewRequest(m, srv.URL, nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("method: %v got: %v want: %v", m, resp.Status, http.StatusMethodNotAllowed)
		}
	}
}
