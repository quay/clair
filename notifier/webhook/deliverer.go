package webhook

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sync"

	"github.com/google/uuid"
	"github.com/quay/clair/config"
	"github.com/quay/zlog"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/internal/httputil"
	"github.com/quay/clair/v4/internal/json"
	"github.com/quay/clair/v4/internal/json/jsontext"
)

// SignedOnce is used to print a deprecation notice, but only once per run.
var signedOnce sync.Once

type Deliverer struct {
	// a client to use for POSTing webhooks
	c        *http.Client
	callback *url.URL
	target   *url.URL
	signer   Signer
	headers  http.Header
}

type Signer interface {
	Sign(context.Context, *http.Request) error
}

// New returns a new webhook Deliverer
func New(conf *config.Webhook, client *http.Client, signer Signer) (*Deliverer, error) {
	switch {
	case conf == nil:
		return nil, errors.New("config not provided")
	case client == nil:
		return nil, errors.New("http client not provided")
	}
	var d Deliverer
	var err error

	d.callback, err = url.Parse(conf.Callback)
	if err != nil {
		return nil, err
	}
	d.target, err = url.Parse(conf.Target)
	if err != nil {
		return nil, err
	}
	d.headers = conf.Headers.Clone()
	if d.headers == nil {
		d.headers = make(map[string][]string)
	}
	d.headers.Set("content-type", "application/json")
	d.signer = signer

	d.c = client
	return &d, nil
}

func (d *Deliverer) Name() string {
	return "webhook"
}

var options = sync.OnceValue(func() json.Options {
	return json.WithMarshalers(json.MarshalToFunc(marshalCallback))
})

func marshalCallback(enc *jsontext.Encoder, cb *callbackRequest) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(`callback`)); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(cb.URL.String())); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(`notification_id`)); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(cb.ID.String())); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

type callbackRequest struct {
	ID  *uuid.UUID
	URL *url.URL
}

// Deliver implements the notifier.Deliverer interface.
//
// Deliver POSTs a webhook data structure to the configured target.
func (d *Deliverer) Deliver(ctx context.Context, nID uuid.UUID) error {
	ctx = zlog.ContextWithValues(ctx,
		"component", "notifier/webhook/Deliverer.Deliver",
		"notification_id", nID.String(),
	)

	url, err := d.callback.Parse(nID.String())
	if err != nil {
		return err
	}
	cb := callbackRequest{
		ID:  &nID,
		URL: url,
	}

	rd, wr := io.Pipe()
	defer rd.Close()
	go func() {
		err := json.MarshalWrite(wr, &cb, options())
		wr.CloseWithError(err)
	}()

	req, err := httputil.NewRequestWithContext(ctx, http.MethodPost, d.target.String(), rd)
	if err != nil {
		return err
	}
	for k, vs := range d.headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if d.signer != nil {
		if err := d.signer.Sign(ctx, req); err != nil {
			return err
		}
	}

	zlog.Info(ctx).
		Stringer("callback", url).
		Stringer("target", d.target).
		Msg("dispatching webhook")

	resp, err := d.c.Do(req)
	if err != nil {
		return &clairerror.ErrDeliveryFailed{E: err}
	}
	defer resp.Body.Close()
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
