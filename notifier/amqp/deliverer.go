package amqp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path"

	"github.com/google/uuid"
	"github.com/quay/clair/config"
	amqp "github.com/rabbitmq/amqp091-go"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/notifier"
)

// Deliverer is an AMQP deliverer which publishes a notifier.Callback to the
// the broker.
//
// It's an error to configure this deliverer with an Exchange that does not exist.
// Administrators should configure the Exchange, Queue, and Bindings before starting
// this deliverer.
type Deliverer struct {
	callback   *url.URL
	fo         failOver
	routingKey string
	exchange   config.Exchange
	rollup     int
	direct     bool
}

func New(conf *config.AMQP) (*Deliverer, error) {
	var d Deliverer
	if err := d.load(conf); err != nil {
		return nil, err
	}
	return &d, nil
}

func (d *Deliverer) load(conf *config.AMQP) error {
	var err error
	if !conf.Direct {
		d.callback, err = url.Parse(conf.Callback)
		if err != nil {
			return err
		}
	}
	if conf.TLS != nil {
		d.fo.tls, err = conf.TLS.Config()
		if err != nil {
			return err
		}
	}

	// Copy everything else out of the config:
	d.direct = conf.Direct
	d.rollup = conf.Rollup
	d.exchange = conf.Exchange
	d.routingKey = conf.RoutingKey
	d.fo.uris = make([]*url.URL, len(conf.URIs))
	for i, u := range conf.URIs {
		d.fo.uris[i], err = url.Parse(u)
		if err != nil {
			return err
		}
	}
	d.fo.exchange = &d.exchange
	return nil
}

func (d *Deliverer) Name() string {
	return fmt.Sprintf("amqp-%s", d.exchange.Name)
}

func (d *Deliverer) Deliver(ctx context.Context, nID uuid.UUID) error {
	conn, err := d.fo.Connection(ctx)
	if err != nil {
		return &clairerror.ErrDeliveryFailed{err}
	}
	defer conn.Close()

	ch, err := conn.Channel()
	if err != nil {
		return &clairerror.ErrDeliveryFailed{err}
	}
	defer ch.Close()

	callback := *d.callback
	callback.Path = path.Join(callback.Path, nID.String())

	cb := notifier.Callback{
		NotificationID: nID,
		Callback:       callback,
	}
	b, err := json.Marshal(&cb)
	if err != nil {
		return &clairerror.ErrDeliveryFailed{err}
	}
	msg := amqp.Publishing{
		ContentType: "application/json",
		AppId:       "clairV4-notifier",
		Body:        b,
	}
	err = ch.Publish(
		d.exchange.Name,
		d.routingKey,
		false,
		false,
		msg,
	)
	if err != nil {
		return &clairerror.ErrDeliveryFailed{err}
	}
	return nil
}
