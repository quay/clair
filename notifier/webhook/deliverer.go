package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"path"

	"github.com/google/uuid"
	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/notifier"
	"github.com/rs/zerolog"
)

type Deliverer struct {
	conf Config
	// a client to use for POSTing webhooks
	c *http.Client
}

// New returns a new webhook Deliverer
func New(conf Config, client *http.Client) (*Deliverer, error) {
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
	}, nil
}

func (d *Deliverer) Name() string {
	return "webhook"
}

// Deliver implements the notifier.Deliverer interface.
//
// Deliver POSTS a webhook data structure to the configured target.
func (d *Deliverer) Deliver(ctx context.Context, nID uuid.UUID) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "notifier/webhook/deliverer.Deliver").
		Logger()

	callback := d.conf.callback
	callback.Path = path.Join(callback.Path, nID.String())

	wh := notifier.Callback{
		NotificationID: nID,
		Callback:       *callback,
	}
	b, err := json.Marshal(&wh)
	if err != nil {
		return err
	}
	buf := bytes.NewReader(b)

	req := &http.Request{
		URL:    d.conf.target,
		Header: d.conf.Headers,
		Body:   ioutil.NopCloser(buf),
		Method: http.MethodPost,
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
		return &clairerror.ErrDeliveryFailed{err}
	}
	if resp.StatusCode != http.StatusOK {
		return &clairerror.ErrDeliveryFailed{
			&clairerror.ErrRequestFail{
				Code:   resp.StatusCode,
				Status: resp.Status,
			},
		}
	}
	return nil
}
