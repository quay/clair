package amqp

import (
	"context"
	"encoding/json"
	"fmt"
	"path"

	"github.com/google/uuid"
	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/notifier"
	samqp "github.com/streadway/amqp"
)

// Deliverer is an AMQP deliverer which publishes a notifier.Callback to the
// the broker.
//
// It's an error to configure this deliverer with an Exchange that does not exist.
// Administrators should configure the Exchange, Queue, and Bindings before starting
// this deliverer.
type Deliverer struct {
	conf Config
	fo   *failOver
}

func New(conf Config) (*Deliverer, error) {
	var c Config
	var err error
	if c, err = conf.Validate(); err != nil {
		return nil, err
	}
	fo := &failOver{
		Config: c,
	}
	return &Deliverer{
		conf: c,
		fo:   fo,
	}, nil
}

func (d *Deliverer) Name() string {
	return fmt.Sprintf("amqp-%s", d.conf.Exchange.Name)
}

func (d *Deliverer) Deliver(ctx context.Context, nID uuid.UUID) error {
	conn, err := d.fo.Connection(ctx)
	if err != nil {
		return &clairerror.ErrDeliveryFailed{err}
	}

	ch, err := conn.Channel()
	if err != nil {
		return &clairerror.ErrDeliveryFailed{err}
	}
	defer ch.Close()

	callback := d.conf.callback
	callback.Path = path.Join(callback.Path, nID.String())

	cb := notifier.Callback{
		NotificationID: nID,
		Callback:       callback,
	}
	b, err := json.Marshal(&cb)
	if err != nil {
		return &clairerror.ErrDeliveryFailed{err}
	}
	msg := samqp.Publishing{
		ContentType: "application/json",
		AppId:       "clairV4-notifier",
		Body:        b,
	}
	err = ch.Publish(
		d.conf.Exchange.Name,
		d.conf.RoutingKey,
		false,
		false,
		msg,
	)
	if err != nil {
		return &clairerror.ErrDeliveryFailed{err}
	}
	return nil
}
