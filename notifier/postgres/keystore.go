package postgres

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/notifier"
)

var _ notifier.KeyStore = (*KeyStore)(nil)

// KeyStore implements the notifier.KeyStore interface.
// Stored public keys are RSA encoded in PKIX ASN.1 DER form.
type KeyStore struct {
	pool *pgxpool.Pool
}

func NewKeyStore(pool *pgxpool.Pool) *KeyStore {
	return &KeyStore{
		pool: pool,
	}
}

func (k *KeyStore) Keys(ctx context.Context) ([]notifier.Key, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "notifier/postgres/KeyStore.Keys"),
	)
	const (
		query = `SELECT id, expiration, pub_key FROM key WHERE expiration > CURRENT_TIMESTAMP;`
	)

	rows, err := k.pool.Query(ctx, query)
	defer rows.Close()
	if err != nil {
		return nil, err
	}

	type tmp struct {
		id  uuid.UUID
		exp time.Time
		der []byte
	}
	tmps := []tmp{}

	for rows.Next() {
		var t tmp
		err = rows.Scan(&t.id, &t.exp, &t.der)
		if err != nil {
			return nil, err
		}
		tmps = append(tmps, t)
	}
	rows.Close()
	zlog.Debug(ctx).
		Int("len", len(tmps)).
		Msg("discovered keys")

	// process tmp keys, rows are closed so time taken here
	// won't starve conn pool.
	keys := make([]notifier.Key, 0, len(tmps))
	for _, t := range tmps {
		pub, err := derToRSAPublic(t.der)
		if err != nil {
			return nil, err
		}
		keys = append(keys, notifier.Key{
			ID:         t.id,
			Expiration: t.exp,
			Public:     pub,
		})
	}

	return keys, nil
}

func (k *KeyStore) KeyByID(ctx context.Context, ID uuid.UUID) (notifier.Key, error) {
	const (
		query = `SELECT id, expiration, pub_key FROM key WHERE id = $1 AND expiration > CURRENT_TIMESTAMP;`
	)

	var key notifier.Key
	der := []byte{}

	row := k.pool.QueryRow(ctx, query, ID)
	err := row.Scan(&key.ID, &key.Expiration, &der)
	switch err {
	case pgx.ErrNoRows:
		return notifier.Key{}, clairerror.ErrKeyNotFound{ID}
	case nil:
		// hop out
	default:
		// return unhandled error
		return notifier.Key{}, err
	}

	pub, err := derToRSAPublic(der)
	if err != nil {
		return notifier.Key{}, err
	}
	key.Public = pub
	return key, nil
}

func (k *KeyStore) PutKey(ctx context.Context, ID uuid.UUID, key *rsa.PublicKey, n time.Duration) error {
	const (
		query = `INSERT INTO key (id, pub_key, expiration) VALUES ($1, $2, CURRENT_TIMESTAMP + $3)`
	)
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return fmt.Errorf("could not marshal provided public key to PKIX, ASN.1 DER form")
	}
	tag, err := k.pool.Exec(ctx, query, ID, der, n.String())
	if err != nil {
		return err
	}
	if tag.RowsAffected() <= 0 {
		return fmt.Errorf("insertion did not affect any rows")
	}
	return nil
}

func (k *KeyStore) DeleteKey(ctx context.Context, ID uuid.UUID) error {
	const (
		query = "DELETE FROM key WHERE id = $1"
	)
	tag, err := k.pool.Exec(ctx, query, ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() <= 0 {
		return clairerror.ErrKeyNotFound{ID}
	}
	return nil
}

func (k *KeyStore) BumpExpiration(ctx context.Context, ID uuid.UUID, n time.Duration) error {
	const (
		query = `UPDATE key SET expiration = CURRENT_TIMESTAMP + $1 WHERE id = $2;`
	)
	tag, err := k.pool.Exec(ctx, query, n.String(), ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() <= 0 {
		return clairerror.ErrKeyNotFound{ID}
	}
	return nil
}

func (k *KeyStore) GC(ctx context.Context) (int64, error) {
	const (
		query = `DELETE FROM key WHERE id = ANY(array(SELECT id FROM key WHERE CURRENT_TIMESTAMP > expiration ORDER BY expiration LIMIT 100));`
	)
	tag, err := k.pool.Exec(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("received error when deleting expired keys: %v", err)
	}
	return tag.RowsAffected(), nil
}

// derToRSAPublic is a helper method converting a PKIX, ASN.1 DER form
// byte slice to a *rsa.PublicKey data structure.
func derToRSAPublic(der []byte) (*rsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	var rsaPub *rsa.PublicKey
	var ok bool
	if rsaPub, ok = pub.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("could not type assert parsed PKIX public key to rsa.PublicKey")
	}
	return rsaPub, nil
}
