package amqp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/quay/clair/config"
	amqp "github.com/rabbitmq/amqp091-go"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/notifier"
)

// DirectDeliverer is an AMQP deliverer which publishes notifications
// directly to the broker.
//
// It's an error to configure this deliverer with an exchange that does not exist.
// Administrators should configure the Exchange, Queue, and Bindings before starting
// this deliverer.
type DirectDeliverer struct {
	n []notifier.Notification
	Deliverer
}

func NewDirectDeliverer(conf *config.AMQP) (*DirectDeliverer, error) {
	var d DirectDeliverer
	if err := d.load(conf); err != nil {
		return nil, err
	}
	d.n = make([]notifier.Notification, 0, 1024)
	return &d, nil
}

func (d *DirectDeliverer) Name() string {
	return fmt.Sprintf("amqp-direct-%s", d.exchange.Name)
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
	tmp := make([]notifier.Notification, len(n))
	copy(tmp, n)
	d.n = tmp
	return nil
}

func (d *DirectDeliverer) Deliver(ctx context.Context, _ uuid.UUID) error {
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

	err = ch.Tx()
	if err != nil {
		return &clairerror.ErrDeliveryFailed{err}
	}
	// TODO: can tx.Rollback be safely defered?

	// block loop publishing smaller blocks of max(rollup) length via reslicing.
	rollup := d.rollup
	if rollup == 0 {
		rollup++
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	var currentBlock []notifier.Notification
	for bs, be := 0, rollup; bs < len(d.n); bs, be = be, be+rollup {
		buf.Reset()
		// if block-end exceeds array bounds, slice block underflow.
		// next block-start will cause loop to exit.
		if be > len(d.n) {
			be = len(d.n)
		}

		currentBlock = d.n[bs:be]
		err := enc.Encode(&currentBlock)
		if err != nil {
			ch.TxRollback()
			return &clairerror.ErrDeliveryFailed{err}
		}
		msg := amqp.Publishing{
			ContentType: "application/json",
			AppId:       "clairV4-notifier",
			Body:        buf.Bytes(),
		}
		err = ch.Publish(
			d.exchange.Name,
			d.routingKey,
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
