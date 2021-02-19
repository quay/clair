package stomp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	gostomp "github.com/go-stomp/stomp"
	"github.com/google/uuid"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/notifier"
)

// Deliverer is a STOMP deliverer which publishes a notifier.Callback to the
// the broker.
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
	return fmt.Sprintf("stomp-direct-%s", d.conf.Destination)
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
	tmp := make([]notifier.Notification, len(n), len(n))
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
	var rollup int = d.conf.Rollup
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
		err = tx.Send(d.conf.Destination, "application/json", buf.Bytes(), gostomp.SendOpt.Receipt)
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
