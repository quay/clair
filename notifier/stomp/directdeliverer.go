package stomp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	gostomp "github.com/go-stomp/stomp/v3"
	"github.com/google/uuid"
	"github.com/quay/clair/config"

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
		return &clairerror.ErrDeliveryFailed{err}
	}
	defer conn.Disconnect()

	tx, err := conn.BeginWithError()
	if err != nil {
		return &clairerror.ErrDeliveryFailed{err}
	}

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
			tx.Abort()
			return &clairerror.ErrDeliveryFailed{err}
		}
		err = tx.Send(d.destination, "application/json", buf.Bytes(), gostomp.SendOpt.Receipt)
		if err != nil {
			tx.Abort()
			return &clairerror.ErrDeliveryFailed{err}
		}
	}

	err = tx.Commit()
	if err != nil {
		return &clairerror.ErrDeliveryFailed{err}
	}
	return nil
}
