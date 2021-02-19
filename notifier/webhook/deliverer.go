package webhook

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/internal/codec"
	"github.com/quay/clair/v4/notifier"
	"github.com/quay/clair/v4/notifier/keymanager"
)

type Deliverer struct {
	conf Config
	// a client to use for POSTing webhooks
	c    *http.Client
	kmgr *keymanager.Manager
}

// New returns a new webhook Deliverer
func New(conf Config, client *http.Client, keymanager *keymanager.Manager) (*Deliverer, error) {
	var c Config
	var err error
	if c, err = conf.Validate(); err != nil {
		return nil, err
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &Deliverer{
		conf: c,
		c:    client,
		kmgr: keymanager,
	}, nil
}

func (d *Deliverer) Name() string {
	return "webhook"
}

// sign will use the provided private key to sign and attach a jwt to the provided
// request.
func (d *Deliverer) sign(ctx context.Context, req *http.Request, kp keymanager.KeyPair) error {
	opts := (&jose.SignerOptions{}).
		WithType("JWT").
		WithHeader(jose.HeaderKey("kid"), kp.ID.String())
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS512, Key: kp.Private}, opts)
	if err != nil {
		return fmt.Errorf("failed to create jwt signer: %v", err)
	}
	now := jwt.NumericDate(time.Now().Unix())
	expire := jwt.NumericDate(time.Now().Add(1 * time.Hour).Unix())
	cl := jwt.Claims{
		Issuer:   "notifier",
		Expiry:   &expire,
		IssuedAt: &now,
		Audience: jwt.Audience{d.conf.target.String()},
		Subject:  d.conf.target.Hostname(),
	}
	token, err := jwt.Signed(signer).Claims(cl).CompactSerialize()
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

// Deliver implements the notifier.Deliverer interface.
//
// Deliver POSTS a webhook data structure to the configured target.
func (d *Deliverer) Deliver(ctx context.Context, nID uuid.UUID) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "notifier/webhook/deliverer.Deliver").
		Str("notification_id", nID.String()).
		Logger()

	callback, err := d.conf.callback.Parse(nID.String())
	if err != nil {
		return err
	}

	wh := notifier.Callback{
		NotificationID: nID,
		Callback:       *callback,
	}

	req := &http.Request{
		URL:    d.conf.target,
		Header: d.conf.Headers,
		Body:   codec.JSONReader(&wh),
		Method: http.MethodPost,
	}

	// sign a jwt using key manager's private key
	if d.conf.Signed {
		kp, err := d.kmgr.KeyPair()
		if err != nil {
			return fmt.Errorf("configured for signing but no private key available: %v", err)
		}
		err = d.sign(ctx, req, kp)
		if err != nil {
			return fmt.Errorf("failed to sign request: %v", err)
		}
		log.Debug().Msg("successfully signed request")
	}

	log.Info().Str("notification_id", nID.String()).
		Str("callback", callback.String()).
		Str("target", d.conf.Target).
		Msg("dispatching webhook")

	resp, err := d.c.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return &clairerror.ErrDeliveryFailed{E: err}
	}
	if resp.StatusCode != http.StatusOK {
		return &clairerror.ErrDeliveryFailed{
			E: &clairerror.ErrRequestFail{
				Code:   resp.StatusCode,
				Status: resp.Status,
			},
		}
	}
	return nil
}
