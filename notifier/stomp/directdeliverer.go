package stomp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/quay/clair/config"
	"github.com/quay/zlog"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/notifier"
)

// Deliverer is a STOMP deliverer which publishes a notifier.Callback to the
// the broker.
type DirectDeliverer struct {
	Deliverer
	n []notifier.Notification
}

func NewDirectDeliverer(conf *config.STOMP) (*DirectDeliverer, error) {
	var d DirectDeliverer
	if err := d.load(conf); err != nil {
		return nil, err
	}
	d.n = make([]notifier.Notification, 0, 1024)
	return &d, nil
}

func (d *DirectDeliverer) Name() string {
	return fmt.Sprintf("stomp-direct-%s", d.destination)
}

// Notifications will copy the provided notifications into a buffer for STOMP
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

func (d *DirectDeliverer) Deliver(ctx context.Context, nID uuid.UUID) error {
	conn, err := d.fo.Connection(ctx)
	if err != nil {
		return errDeliever(err)
	}
	defer conn.Disconnect()

	tx, err := conn.BeginWithError()
	if err != nil {
		return errDeliever(err)
	}
	var success bool
	defer func() {
		if success {
			return
		}
		if err := tx.AbortWithReceipt(); err != nil {
			zlog.Warn(ctx).Err(err).Msg("transaction aborted")
		}
	}()

	// block loop publishing smaller blocks of max(rollup) length via reslicing.
	rollup := d.rollup
	if rollup == 0 {
		rollup++
	}

	var currentBlock []notifier.Notification
	for bs, be := 0, rollup; bs < len(d.n); bs, be = be, be+rollup {
		// If block-end exceeds array bounds, slice block underflow.
		// Next block-start will cause loop to exit.
		if be > len(d.n) {
			be = len(d.n)
		}

		currentBlock = d.n[bs:be]
		// Can't reuse a buffer because without receipts, the client returns
		// after queuing the send.
		// Can't use receipts because RabbitMQ treats receipt as a thing that
		// happens at the end of a transaction (not unreasonable, I suppose).
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(&currentBlock); err != nil {
			return errDeliever(err)
		}
		if err := tx.Send(d.destination, "application/json", buf.Bytes(), nil); err != nil {
			return errDeliever(err)
		}
	}

	if err := tx.CommitWithReceipt(); err != nil {
		return errDeliever(err)
	}
	success = true
	return nil
}

func errDeliever(e error) error {
	return &clairerror.ErrDeliveryFailed{E: e}
}
