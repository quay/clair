package httptransport

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path"
	"testing"
	"time"

	"github.com/google/uuid"
	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/notifier"
	jose "gopkg.in/square/go-jose.v2"
)

func TestKeyByIDHandler(t *testing.T) {
	t.Run("KeyByID", testKeyByID)
	t.Run("Methods", testKeyByIDMethods)
	t.Run("BadPathParam", testKeyByIDBadPathParam)
	t.Run("KeyNotFound", testKeyByIDNotFound)
}

func testKeyByIDNotFound(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	mock := &notifier.MockKeyStore{
		KeyByID_: func(ctx context.Context, ID uuid.UUID) (notifier.Key, error) {
			return notifier.Key{}, clairerror.ErrKeyNotFound{id}
		},
	}

	h := KeyByIDHandler(mock)
	rr := httptest.NewRecorder()
	path := path.Join("/", id.String())
	req, err := http.NewRequest(http.MethodGet, path, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("got: %v want: %v", rr.Code, http.StatusNotFound)
	}
}

func testKeyByIDBadPathParam(t *testing.T) {
	h := KeyByIDHandler(&notifier.MockKeyStore{})

	rr := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/bad-uuid", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("want %v got %v", rr.Code, http.StatusBadRequest)
	}

	rr = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("want %v got %v", rr.Code, http.StatusBadRequest)
	}
}

func testKeyByID(t *testing.T) {
	t.Parallel()
	kp := (genKeyPair(t, 1))[0]
	exp := time.Now().Add(10 * time.Minute)
	key := notifier.Key{kp.ID, exp, kp.Public}

	mock := &notifier.MockKeyStore{
		KeyByID_: func(ctx context.Context, ID uuid.UUID) (notifier.Key, error) {
			if ID != kp.ID {
				t.Fatalf("got %v want %v", ID, kp.ID)
			}
			return key, nil
		},
	}

	h := KeyByIDHandler(mock)
	rr := httptest.NewRecorder()
	path := path.Join("/", kp.ID.String())
	req, err := http.NewRequest(http.MethodGet, path, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("request failed: %v", rr.Code)
	}

	var jwk jose.JSONWebKey
	if err := json.NewDecoder(rr.Body).Decode(&jwk); err != nil {
		t.Fatalf("failed to deserialize response: %v", err)
	}

	pub, ok := jwk.Key.(*rsa.PublicKey)
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

// testKeyByIDMethods confirms the handler only responds
// to the desired methods.
func testKeyByIDMethods(t *testing.T) {
	t.Parallel()
	h := KeyByIDHandler(&notifier.MockKeyStore{})
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
