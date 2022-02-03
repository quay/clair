package notifier

import (
	"context"
	"errors"
	"time"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/zlog"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/matcher"
)

const (
	// max number of UOIDs that we will queue in a channel
	MaxChanSize = 1024
)

// PollerOpt applies a configuration to a Poller
type PollerOpt func(*Poller) error

// Poller implements new Update Operation discovery via an event channel.
type Poller struct {
	// a store to retrieve known UOIDs and compare
	// with the polled UOIDs.
	store Store
	// a differ to retrieve latest update operations
	differ matcher.Differ
	// the interval to poll a Matcher node.
	interval time.Duration
}

func NewPoller(store Store, differ matcher.Differ, interval time.Duration) *Poller {
	return &Poller{
		interval: interval,
		store:    store,
		differ:   differ,
	}
}

// Event is delivered on the poller's channel when a new UpdateOperation is
// discovered.
type Event struct {
	updater string
	uo      driver.UpdateOperation
}

// Poll begins polling the Matcher for UpdateOperations and producing Events on
// the supplied channel. This method takes ownership of the channel and is
// responsible for closing it.
//
// Cancel ctx to stop the poller.
func (p *Poller) Poll(ctx context.Context, c chan<- Event) error {
	ctx = zlog.ContextWithValues(ctx, "component", "notifier/Poller.poll")

	defer close(c)
	if err := ctx.Err(); err != nil {
		zlog.Info(ctx).
			Msg("context canceled before polling began")
		return err
	}

	// loop on interval tick
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			zlog.Info(ctx).
				Msg("context canceled. polling ended")
			return ctx.Err()
		case <-t.C:
			zlog.Debug(ctx).
				Msg("poll interval tick")
			p.onTick(ctx, c)
		}
	}
}

// OnTick retrieves the latest update operations for all known updaters and
// delivers an event if notification creation is necessary.
func (p *Poller) onTick(ctx context.Context, c chan<- Event) {
	ctx = zlog.ContextWithValues(ctx, "component", "notifier/Poller.onTick")

	latest, err := p.differ.LatestUpdateOperations(ctx, driver.VulnerabilityKind)
	if err != nil {
		zlog.Error(ctx).
			Err(err).
			Msg("client error retrieving latest update operations. backing off until next interval")
		return
	}

	for updater, uo := range latest {
		ctx := zlog.ContextWithValues(ctx, "updater", updater)
		if len(uo) == 0 {
			zlog.Debug(ctx).
				Msg("received 0 update operations after polling Matcher")
			return // Should this be a continue?
		}
		latest := uo[0]
		ctx = zlog.ContextWithValues(ctx, "UOID", latest.Ref.String())
		// confirm notifications were never created for this UOID.
		var errNoReceipt *clairerror.ErrNoReceipt
		_, err := p.store.ReceiptByUOID(ctx, latest.Ref)
		if errors.As(err, &errNoReceipt) {
			e := Event{
				updater: updater,
				uo:      latest,
			}
			select {
			case c <- e:
			default:
				zlog.Warn(ctx).
					Msg("could not deliver event to channel. skipping updater now")
			}
			continue
		}
		if err != nil {
			zlog.Error(ctx).
				Err(err).
				Msg("received error getting receipt by UOID. backing off till next tick")
			return
		}
	}
}
