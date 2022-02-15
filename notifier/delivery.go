package notifier

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/quay/zlog"

	clairerror "github.com/quay/clair/v4/clair-error"
)

// Delivery handles the business logic of delivering
// notifications.
type Delivery struct {
	// a Deliverer implementation to invoke.
	Deliverer Deliverer
	// the interval at which we will attempt delivery of notifications.
	interval time.Duration
	// a store to retrieve notifications and update their receipts
	store Store
	// distributed lock used for mutual exclusion
	locks Locker
	// a integer id used for logging
	id int
}

func NewDelivery(id int, d Deliverer, interval time.Duration, store Store, l Locker) *Delivery {
	return &Delivery{
		Deliverer: d,
		interval:  interval,
		store:     store,
		locks:     l,
		id:        id,
	}
}

// Deliver begins delivering notifications.
//
// Canceling the ctx will end delivery.
func (d *Delivery) Deliver(ctx context.Context) {
	ctx = zlog.ContextWithValues(ctx,
		"deliverer", d.Deliverer.Name(),
		"component", "notifier/Delivery.Deliver",
		"id", strconv.Itoa(d.id),
	)
	zlog.Info(ctx).
		Msg("delivering notifications")
	go d.deliver(ctx)
}

// deliver is intended to be ran as a go routine.
//
// implements a blocking event loop via a time.Ticker
func (d *Delivery) deliver(ctx context.Context) error {
	ctx = zlog.ContextWithValues(ctx, "component", "notifier/Delivery.deliver")

	defer func() {
		if err := d.locks.Close(ctx); err != nil {
			zlog.Warn(ctx).Err(err).Msg("error closing lock source")
		}
	}()
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
	ctx = zlog.ContextWithValues(ctx,
		"deliverer", d.Deliverer.Name(),
		"id", strconv.Itoa(d.id),
		"component", "notifier/Delivery.RunDelivery",
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
		var err error
		ctx, done := d.locks.TryLock(ctx, nID.String())
		if ok := ctx.Err(); !errors.Is(ok, nil) {
			zlog.Debug(ctx).
				Err(ok).
				Stringer("notification_id", nID).
				Msg("unable to get lock")
		} else {
			err = d.do(ctx, nID)
		}
		done()
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
	ctx = zlog.ContextWithValues(ctx,
		"notification_id", nID.String(),
		"component", "notifier/Delivery.do",
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
