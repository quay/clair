package keymanager

import (
	"context"
	cRand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"math/rand"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/notifier"
	"github.com/rs/zerolog"
)

const (
	// minutes added to the expiration at time of bump
	delta = 10 * time.Minute
	// interval in which the manager will bump the expiration
	interval = 5 * time.Minute
	// RSA key bit size
	bitSize = 4096
)

// KeyPair is the set of RSA keys held by the lock
// manager.
type KeyPair struct {
	// unique identifier for the key
	ID      uuid.UUID
	Private *rsa.PrivateKey
	Public  *rsa.PublicKey
	// PKIX, ASN.1 DER converted public key
	Der []byte
}

// Manager is responsible for generating an RSA key pair,
// persisting it to storage, and periodically updating its
// key pair expiration.
//
// Clients may use a manager to retrieve the currently managed
// KeyPair for signing.
//
// A Manager should always be constructed via the NewManager constructor.
type Manager struct {
	// holds currently managed key pair
	kp    atomic.Value
	store notifier.KeyStore
}

// NewMananger will return a Mananger with a managed key pair.
//
// Clients may query the manager to retrieve the currently managed key pair.
//
// If the manager fails to create and persist a key pair construction will fail.
//
// Ensure cancelation of ctx to avoid go routine leakage.
func NewManager(ctx context.Context, store notifier.KeyStore) (*Manager, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "notifier/keymanager/NewManager").
		Logger()

	var m *Manager = &Manager{
		kp:    atomic.Value{},
		store: store,
	}
	newKP, err := m.genKeyPair(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to gen key pair: %v", err)
	}
	if err := m.store.PutKey(ctx, newKP.ID, newKP.Public, delta); err != nil {
		return nil, fmt.Errorf("failed to store initial key pair: %v", err)
	}
	// atomic store
	m.kp.Store(&newKP)

	// kick off event loop
	go m.loop(ctx)

	log.Info().Msg("key manager initialized.")
	return m, nil
}

// KeyPair returns the currently managed key pair.
//
// An error is returned if no key pair exists.
func (m *Manager) KeyPair() (KeyPair, error) {
	var kp *KeyPair = (m.kp.Load()).(*KeyPair)
	if kp == nil {
		return KeyPair{}, fmt.Errorf("no managed key")
	}

	return *kp, nil
}

// genKeyPair creates a RSA key pair.
func (m *Manager) genKeyPair(ctx context.Context) (KeyPair, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "notifier/keymanager/Manager.genKeyPair").
		Logger()

	reader := cRand.Reader
	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		return KeyPair{}, fmt.Errorf("failed to generate test key pair: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return KeyPair{}, err
	}

	id := uuid.New()

	log.Debug().Str("id", id.String()).Msg("new key pair generated")
	return KeyPair{
		ID:      id,
		Private: key,
		Public:  &key.PublicKey,
		Der:     der,
	}, nil
}

// loop is a blocking event loop.
func (m *Manager) loop(ctx context.Context) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "notifier/keymanager/Manager.loop").
		Logger()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			log.Debug().Msg("keymanager tick")
			err := m.bump(ctx)
			log.Error().Err(err).Msg("received error when bumping public key expiration")

			// 1/4 chance of running gc
			if rand.Int()%4 == 0 {
				go m.gc(ctx)
			}
		}
	}
}

func (m *Manager) gc(ctx context.Context) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "notifier/keymanager/Manager.gc").
		Logger()

	log.Info().Msg("gc starting")
	var total int64
	var err error
	var n int64 = -1
	for n != 0 {
		n, err = m.store.GC(ctx)
		if err != nil {
			log.Error().Err(err).Msg("received error while performing gc")
		}
		total += n
	}
	log.Info().Int64("deleted", total).Msg("gc complete")
}

// bump will attempt a bump of the currently managed
// key pair.
//
// if the key pair is not found a new key pair is created and managed.
func (m *Manager) bump(ctx context.Context) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "notifier/keymanager/Manager.bump").
		Logger()

	var kp *KeyPair = (m.kp.Load()).(*KeyPair)
	if kp == nil {
		panic("not created via constructor")
	}

	err := m.store.BumpExpiration(ctx, kp.ID, delta)
	switch {
	case errors.As(err, &clairerror.ErrKeyNotFound{}):
		newKP, err := m.genKeyPair(ctx)
		if err != nil {
			return err
		}
		if err := m.store.PutKey(ctx, newKP.ID, newKP.Public, delta); err != nil {
			return err
		}
		// atomic store
		m.kp.Store(&newKP)
		return nil
	case err == nil:
		// hop out
	default:
		return err
	}
	log.Debug().Str("id", kp.ID.String()).Msg("succesfully bump key expiration")
	return nil
}
