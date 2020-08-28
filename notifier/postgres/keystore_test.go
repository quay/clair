package postgres_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/claircore/test/log"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/notifier/keymanager"
	"github.com/quay/clair/v4/notifier/postgres"
)

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

// TestKeyStore is a parellel test harness.
func TestKeyStore(t *testing.T) {
	t.Run("GC", testKeyStoreGC)
	t.Run("KeyStore", testKeyStore)
}

func testKeyStoreGC(t *testing.T) {
	integration.Skip(t)
	t.Parallel()
	ctx, done := log.TestLogger(context.Background(), t)
	defer done()
	db, _, keystore, teardown := postgres.TestStore(ctx, t)
	defer teardown()

	// put some expired keys
	kps := genKeyPair(t, 200)
	for _, kp := range kps {
		err := keystore.PutKey(ctx, kp.ID, kp.Public, -5*time.Minute)
		if err != nil {
			t.Fatalf("failed to store key pair %+v: %v", kp, err)
		}
	}

	// comfirm we don't receive them with an all query
	keys, err := keystore.Keys(ctx)
	if err != nil {
		t.Fatalf("failed to retrieve all keys: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("got: %v want: %v", len(keys), 0)
	}

	// run gc
	var n int64 = -1
	var cycles int64
	for n != 0 {
		n, err = keystore.GC(ctx)
		if err != nil {
			t.Fatalf("gc call failed: %v", err)
		}
		cycles++
	}
	if cycles != 3 {
		t.Errorf("got: %v want: %v", cycles, 2)
	}

	// confirm no keys in db
	var count int64
	query := "SELECT COUNT(*) FROM key;"
	row := db.QueryRow(query)
	err = row.Scan(&count)
	if err != nil {
		t.Fatalf("failed to receive count from db: %v", err)
	}
	if count != 0 {
		t.Errorf("got: %v want: %v", count, 0)
	}

}

func testKeyStore(t *testing.T) {
	integration.Skip(t)
	t.Parallel()
	ctx, done := log.TestLogger(context.Background(), t)
	defer done()
	_, _, keystore, teardown := postgres.TestStore(ctx, t)
	defer teardown()

	kps := genKeyPair(t, 10)

	// put em...
	for _, kp := range kps {
		err := keystore.PutKey(ctx, kp.ID, kp.Public, 5*time.Minute)
		if err != nil {
			t.Fatalf("failed to store key pair %+v: %v", kp, err)
		}
	}
	// get em all...
	keys, err := keystore.Keys(ctx)
	if err != nil {
		t.Errorf("failed to retrieve all keys: %v", err)
	}
	if len(keys) != len(kps) {
		t.Errorf("got: %d, want: %d", len(keys), len(kps))
	}

	// get em by ids...
	for _, kp := range kps {
		key, err := keystore.KeyByID(ctx, kp.ID)
		if err != nil {
			t.Fatalf("failed to retrieve key by id %s: %v", kp.ID, err)
		}
		if key.ID != kp.ID {
			t.Errorf("got: %s, want: %s", key.ID, kp.ID)
		}
		if key.Public.N.Cmp(kp.Public.N) != 0 {
			t.Errorf("got: %X want: %X", key.Public.N, kp.Public.N)
		}
		if key.Public.E != key.Public.E {
			t.Errorf("got: %v want: %v", key.Public.E, kp.Public.E)
		}
	}
	// delete em all
	for _, kp := range kps {
		err := keystore.DeleteKey(ctx, kp.ID)
		if err != nil {
			t.Fatalf("failed to delete key pair %v: %v", kp.ID, err)
		}

		_, err = keystore.KeyByID(ctx, kp.ID)
		if !errors.As(err, &clairerror.ErrKeyNotFound{}) {
			t.Errorf("got: %v, wanted: %v", err, clairerror.ErrKeyNotFound{kp.ID})
		}
	}
}
