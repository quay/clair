package amqp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/notifier"
	samqp "github.com/streadway/amqp"
)

// DirectDeliverer is an AMQP deliverer which publishes notifications
// directly to the broker.
//
// It's an error to configure this deliverer with an exchange that does not exist.
// Administrators should configure the Exchange, Queue, and Bindings before starting
// this deliverer.
type DirectDeliverer struct {
	conf Config
	n    []notifier.Notification
	fo   *failOver
}

func NewDirectDeliverer(conf Config) (*DirectDeliverer, error) {
	var c Config
	var err error
	if c, err = conf.Validate(); err != nil {
		return nil, err
	}
	fo := &failOver{
		Config: c,
	}
	return &DirectDeliverer{
		conf: c,
		n:    []notifier.Notification{},
		fo:   fo,
	}, nil
}

func (d *DirectDeliverer) Name() string {
	return fmt.Sprintf("amqp-direct-%s", d.conf.Exchange.Name)
}

// Notifications will copy the provided notifications into a buffer for AMQP
// delivery.
func (d *DirectDeliverer) Notifications(ctx context.Context, n []notifier.Notification) error {
	// if we can reslice instead of allocate do so.
	if len(n) <= len(d.n) {
		d.n = d.n[:len(n)]
		copy(d.n, n)
		return nil
	}
	tmp := make([]notifier.Notification, len(n), len(n))
	copy(tmp, n)
	d.n = tmp
	return nil
}

func (d *DirectDeliverer) Deliver(ctx context.Context, _ uuid.UUID) error {
	conn, err := d.fo.Connection(ctx)
	if err != nil {
		return &clairerror.ErrDeliveryFailed{err}
	}

	ch, err := conn.Channel()
	if err != nil {
		return &clairerror.ErrDeliveryFailed{err}
	}
	defer ch.Close()

	err = ch.Tx()
	if err != nil {
		return &clairerror.ErrDeliveryFailed{err}
	}
	// TODO: can tx.Rollback be safely defered?

	// block loop publishing smaller blocks of max(rollup) length via reslicing.
	var rollup int = d.conf.Rollup
	if rollup == 0 {
		rollup++
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for bs, be := 0, rollup; bs < len(d.n); bs, be = be, be+rollup {
		buf.Reset()
		// if block-end exceeds array bounds, slice block underflow.
		// next block-start will cause loop to exit.
		if be > len(d.n) {
			be = len(d.n)
		}

		d.n = d.n[bs:be]
		err := enc.Encode(&d.n)
		if err != nil {
			ch.TxRollback()
			return &clairerror.ErrDeliveryFailed{err}
		}
		msg := samqp.Publishing{
			ContentType: "application/json",
			AppId:       "clairV4-notifier",
			Body:        buf.Bytes(),
		}
		err = ch.Publish(
			d.conf.Exchange.Name,
			d.conf.RoutingKey,
			false,
			false,
			msg,
		)
		if err != nil {
			ch.TxRollback()
			return &clairerror.ErrDeliveryFailed{err}
		}
	}

	err = ch.TxCommit()
	if err != nil {
		return &clairerror.ErrDeliveryFailed{err}
	}
	return nil
}
