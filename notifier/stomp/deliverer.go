package stomp

import (
	"context"
	"encoding/json"
	"fmt"
	"path"

	gostomp "github.com/go-stomp/stomp"
	"github.com/google/uuid"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/notifier"
)

// Deliverer is a STOMP deliverer which publishes a notifier.Callback to the
// the broker.
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
	return fmt.Sprintf("stomp-%s", d.conf.Destination)
}

func (d *Deliverer) Deliver(ctx context.Context, nID uuid.UUID) error {
	conn, err := d.fo.Connection(ctx)
	if err != nil {
		return &clairerror.ErrDeliveryFailed{err}
	}
	defer conn.Disconnect()

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

	err = conn.Send(d.conf.Destination, "application/json", b, gostomp.SendOpt.Receipt)
	if err != nil {
		return &clairerror.ErrDeliveryFailed{err}
	}
	return nil
}
