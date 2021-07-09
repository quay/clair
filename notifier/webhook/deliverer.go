package webhook

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/internal/codec"
	"github.com/quay/clair/v4/notifier"
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
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "notifier/webhook/Deliverer.Deliver"),
		label.Stringer("notification_id", nID),
	)

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

	zlog.Info(ctx).
		Stringer("callback", callback).
		Stringer("target", d.conf.target).
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
