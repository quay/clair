package notifier

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/quay/claircore/pkg/distlock"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	clairerror "github.com/quay/clair/v4/clair-error"
)

// Delivery handles the business logic of delivering
// notifications.
type Delivery struct {
	// a Deliverer implemention to invoke.
	Deliverer Deliverer
	// the interval at which we will attempt delivery of notifications.
	interval time.Duration
	// a store to retrieve notifications and update their receipts
	store Store
	// distributed lock used for mutual exclusion
	distLock distlock.Locker
	// a integer id used for logging
	id int
}

func NewDelivery(id int, d Deliverer, interval time.Duration, store Store, distLock distlock.Locker) *Delivery {
	return &Delivery{
		Deliverer: d,
		interval:  interval,
		store:     store,
		distLock:  distLock,
		id:        id,
	}
}

// Deliver begins delivering notifications.
//
// Canceling the ctx will end delivery.
func (d *Delivery) Deliver(ctx context.Context) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("deliverer", d.Deliverer.Name()),
		label.String("component", "notifier/Delivery.Deliver"),
		label.Int("id", d.id),
	)
	zlog.Info(ctx).
		Msg("delivering notifications")
	go d.deliver(ctx)
}

// deliver is intended to be ran as a go routine.
//
// implements a blocking event loop via a time.Ticker
func (d *Delivery) deliver(ctx context.Context) error {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "notifier/Delivery.deliver"),
	)

	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			zlog.Debug(ctx).
				Msg("delivery tick")
			err := d.RunDelivery(ctx)
			if err != nil {
				zlog.Error(ctx).
					Err(err).
					Msg("encountered error on tick")
			}
		}
	}
}

// RunDelivery determines notifications to deliver and
// calls the implemented Deliverer to perform the actions.
func (d *Delivery) RunDelivery(ctx context.Context) error {
	ctx = baggage.ContextWithValues(ctx,
		label.String("deliverer", d.Deliverer.Name()),
		label.Int("id", d.id),
		label.String("component", "notifier/Delivery.RunDelivery"),
	)

	toDeliver := []uuid.UUID{}
	// get created
	created, err := d.store.Created(ctx)
	if err != nil {
		return err
	}
	if sz := len(created); sz != 0 {
		zlog.Info(ctx).
			Int("created", sz).
			Msg("notification ids in created status")
		toDeliver = append(toDeliver, created...)
	}

	// get failed
	failed, err := d.store.Failed(ctx)
	if err != nil {
		return err
	}
	if sz := len(failed); sz != 0 {
		zlog.Info(ctx).
			Int("failed", sz).
			Msg("notification ids in failed status")
		toDeliver = append(toDeliver, failed...)
	}

	for _, nID := range toDeliver {
		ok, err := d.distLock.TryLock(ctx, nID.String())
		if err != nil {
			// distlock failed, back off till next tick
			return err
		}
		if !ok {
			zlog.Debug(ctx).
				Stringer("notification_id", nID).
				Msg("another process is delivering this notification")
			// another process is working on this notification
			continue
		}
		// an error means we should back off until next tick
		err = d.do(ctx, nID)
		d.distLock.Unlock()
		if err != nil {
			return err
		}
	}
	return nil
}

// do performs the delivery of notifications via the composed
// deliverer
//
// do's actions should be performed under a distributed lock.
func (d *Delivery) do(ctx context.Context, nID uuid.UUID) error {
	ctx = baggage.ContextWithValues(ctx,
		label.Stringer("notification_id", nID),
		label.String("component", "notifier/Delivery.do"),
	)

	// if we have a direct deliverer provide the notifications to it.
	if dd, ok := d.Deliverer.(DirectDeliverer); ok {
		zlog.Debug(ctx).
			Msg("providing direct deliverer notifications")
		notifications, _, err := d.store.Notifications(ctx, nID, nil)
		if err != nil {
			return err
		}
		err = dd.Notifications(ctx, notifications)
		if err != nil {
			return err
		}
	}

	// deliver the notification
	err := d.Deliverer.Deliver(ctx, nID)
	if err != nil {
		var dErr clairerror.ErrDeliveryFailed
		if errors.As(err, &dErr) {
			// OK for this to fail, notification will stay in Created status.
			// store is failing, lets back off it tho until next tick.
			zlog.Info(ctx).
				Msg("failed to deliver notifications")
			err := d.store.SetDeliveryFailed(ctx, nID)
			if err != nil {
				return err
			}
			return nil
		}
		return err
	}
	err = d.store.SetDelivered(ctx, nID)
	if err != nil {
		// the message was delivered, but we can't ack this in our db
		// it will be delivered again unless deleted before next interval
		return err
	}

	// if we successfully performed direct delivery
	// we can delete notification id
	if _, ok := d.Deliverer.(DirectDeliverer); ok {
		err := d.store.SetDeleted(ctx, nID)
		if err != nil {
			return err
		}
	}
	zlog.Info(ctx).
		Msg("successfully delivered notifications")
	return nil
}
