package notifier

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/claircore/pkg/distlock"
	"github.com/rs/zerolog"
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
	id uint8
}

func NewDelivery(id int, d Deliverer, interval time.Duration, store Store, distLock distlock.Locker) *Delivery {
	return &Delivery{
		Deliverer: d,
		interval:  interval,
		store:     store,
		distLock:  distLock,
		id:        uint8(id),
	}
}

// Deliver begins delivering notifications.
//
// Canceling the ctx will end delivery.
func (d *Delivery) Deliver(ctx context.Context) {
	log := zerolog.Ctx(ctx).With().Uint8("id", d.id).
		Str("deliverer", d.Deliverer.Name()).
		Str("component", "notifier/delivery/Delivery.Deliver").Logger()
	log.Info().Msg("delivering notifications")
	go d.deliver(ctx)
}

// deliver is intended to be ran as a go routine.
//
// implements a blocking event loop via a time.Ticker
func (d *Delivery) deliver(ctx context.Context) error {
	log := zerolog.Ctx(ctx).With().
		Str("deliverer", d.Deliverer.Name()).
		Uint8("id", d.id).
		Str("component", "notifier/delivery/Delivery.deliver").Logger()

	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			log.Debug().Msg("delivery tick")
			err := d.RunDelivery(ctx)
			if err != nil {
				log.Error().Err(err).Msg("encountered error on tick")
			}
		}
	}
}

// RunDelivery determines notifications to deliver and
// calls the implemented Deliverer to perform the actions.
func (d *Delivery) RunDelivery(ctx context.Context) error {
	log := zerolog.Ctx(ctx).With().
		Str("deliverer", d.Deliverer.Name()).
		Uint8("id", d.id).
		Str("component", "notifier/delivery/Delivery.RunDelivery").Logger()

	toDeliver := []uuid.UUID{}
	// get created
	if created, err := d.store.Created(ctx); err != nil {
		return err
	} else {
		log.Info().Int("created", len(created)).Msg("notification ids in created status")
		toDeliver = append(toDeliver, created...)
	}

	// get failed
	if failed, err := d.store.Failed(ctx); err != nil {
		return err
	} else {
		log.Info().Int("failed", len(failed)).Msg("notification ids in failed status")
		toDeliver = append(toDeliver, failed...)
	}

	for _, nID := range toDeliver {
		ok, err := d.distLock.TryLock(ctx, nID.String())
		if err != nil {
			// distlock failed, back off till next tick
			return err
		}
		if !ok {
			log.Debug().Str("notification_id", nID.String()).Msg("another process is deliverying this notification")
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
	log := zerolog.Ctx(ctx).With().
		Str("deliverer", d.Deliverer.Name()).
		Uint8("id", d.id).
		Str("component", "notifier/delivery/Delivery.do").Logger()

	// if we have a direct deliverer provide the notifications to it.
	if dd, ok := d.Deliverer.(DirectDeliverer); ok {
		log.Debug().Msg("providing direct deliverer notifications")
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
			log.Info().Str("notifcation_id", nID.String()).Msg("failed to deliver notifications")
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
	log.Info().Str("notifcation_id", nID.String()).Msg("successfully delivered notifications")
	return nil
}
