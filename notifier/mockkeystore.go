package notifier

import (
	"context"
	"crypto/rsa"
	"time"

	"github.com/google/uuid"
)

var _ KeyStore = (*MockKeyStore)(nil)

// MockKeyStore implements a mock KeyStore.
type MockKeyStore struct {
	Keys_           func(ctx context.Context) ([]Key, error)
	KeyByID_        func(ctx context.Context, ID uuid.UUID) (Key, error)
	PutKey_         func(ctx context.Context, ID uuid.UUID, key *rsa.PublicKey, n time.Duration) error
	DeleteKey_      func(ctx context.Context, ID uuid.UUID) error
	BumpExpiration_ func(ctx context.Context, ID uuid.UUID, n time.Duration) error
	GC_             func(ctx context.Context) (n int64, err error)
}

// Keys returns all stored public keys.
func (m *MockKeyStore) Keys(ctx context.Context) ([]Key, error) {
	return m.Keys_(ctx)
}

// KeyByID returns a public key if exists.
// Returns clairerror.ErrKeyNotFound if key does not exist.
func (m *MockKeyStore) KeyByID(ctx context.Context, ID uuid.UUID) (Key, error) {
	return m.KeyByID_(ctx, ID)
}

// PutKey persists a public key with a default expiration of 5 minutes.
//
// A BumpExpiration call is expected to occur sometime before this default
// expiration.
func (m *MockKeyStore) PutKey(ctx context.Context, ID uuid.UUID, key *rsa.PublicKey, n time.Duration) error {
	return m.PutKey_(ctx, ID, key, n)
}

// DeleteKey removes a public key from the keystore.
//
// Returns clairerror.ErrKeyNotFound if key does not exist.
func (m *MockKeyStore) DeleteKey(ctx context.Context, ID uuid.UUID) error {
	return m.DeleteKey(ctx, ID)
}

// BumpExpiration sets the public key's expiration to (n minutes) +
// (time of call).
func (m *MockKeyStore) BumpExpiration(ctx context.Context, ID uuid.UUID, n time.Duration) error {
	return m.BumpExpiration_(ctx, ID, n)
}

// GC performs garbage collection of expired public certificates.
// N is the number of records deleted.
//
// Implementations are free to define efficient GC procedures.
// Callers of this method may repeat GC until 0 is returned.
func (m *MockKeyStore) GC(ctx context.Context) (n int64, err error) {
	return m.GC_(ctx)
}
