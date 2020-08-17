package notifier

import (
	"context"
	"crypto/rsa"
	"time"

	"github.com/google/uuid"
)

type Key struct {
	ID         uuid.UUID
	Expiration time.Time
	Public     *rsa.PublicKey
}

// KeyStore stores and retrieves RSA public keys in
// PKIX, ASN.1 DER form
//
// internally x509.ParsePKIXPublicKey is used to parse and return a *rsa.PublicKey to the caller.
type KeyStore interface {
	// Keys returns all stored public keys.
	Keys(ctx context.Context) ([]Key, error)
	// KeyByID returns a public key if exists.
	// Returns clairerror.ErrKeyNotFound if key does not exist.
	KeyByID(ctx context.Context, ID uuid.UUID) (Key, error)
	// PutKey persists a public key with an initial expiration of n + current time.
	//
	// BumpExpiration is expected to be called periodically to keep the public key alive.
	PutKey(ctx context.Context, ID uuid.UUID, key *rsa.PublicKey, n time.Duration) error
	// DeleteKey removes a public key from the keystore.
	//
	// Returns clairerror.ErrKeyNotFound if key does not exist.
	DeleteKey(ctx context.Context, ID uuid.UUID) error
	// BumpExpiration sets the public key's expiration to n +
	// current time.
	BumpExpiration(ctx context.Context, ID uuid.UUID, n time.Duration) error
	// GC performs garbage collection o f expired public certificates.
	// N is the number of records deleted.
	//
	// Implementations are free to define efficient GC procedures.
	// Callers of this method may repeat GC until 0 is returned.
	GC(ctx context.Context) (n int64, err error)
}
