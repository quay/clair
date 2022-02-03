package notifier

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/zlog"
	"golang.org/x/sync/errgroup"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/matcher"
)

// Processor listen for new UOIDs, creates notifications, and persists
// these notifications for later retrieval.
//
// Processor(s) create atomic boundaries, no two Processor(s) will be creating
// notifications for the same UOID at once.
type Processor struct {
	// distributed lock used for mutual exclusion
	locks Locker
	// a handle to an indexer service
	indexer indexer.Service
	// a handle to a matcher service
	matcher matcher.Service
	// a store instance to persist notifications
	store Store

	// NoSummary controls whether per-manifest vulnerability summarization
	// should happen.
	//
	// The zero value makes the default behavior to do the summary.
	NoSummary bool
}

func NewProcessor(store Store, l Locker, indexer indexer.Service, matcher matcher.Service) *Processor {
	return &Processor{
		locks:   l,
		indexer: indexer,
		matcher: matcher,
		store:   store,
	}
}

// Process receives new UOs as events, creates and persists notifications, and
// updates the notifier system with the "latest" seen UOID.
//
// Canceling the ctx will end the processing.
func (p *Processor) Process(ctx context.Context, c <-chan Event) error {
	ctx = zlog.ContextWithValues(ctx, "component", "notifier/Processor.process")

	zlog.Debug(ctx).Msg("processing events")
	for {
		select {
		case <-ctx.Done():
			zlog.Info(ctx).Msg("context canceled: ending event processing")
			return ctx.Err()
		case e := <-c:
			ctx := zlog.ContextWithValues(ctx,
				"updater", e.updater,
				"UOID", e.uo.Ref.String(),
			)
			zlog.Debug(ctx).Msg("processing")
			if err := func() error {
				ctx, done := p.locks.TryLock(ctx, e.uo.Ref.String())
				defer done()
				if err := ctx.Err(); err != nil {
					return err
				}
				safe, prev := p.safe(ctx, e)
				if !safe {
					return nil
				}
				return p.create(ctx, e, prev)
			}(); err != nil {
				zlog.Error(ctx).
					Err(err).
					Msg("failed to create notifications")
			}
		}
	}
}

// create implements the business logic of creating and persisting
// notifications
//
// will be performed under a distributed lock
func (p *Processor) create(ctx context.Context, e Event, prev uuid.UUID) error {
	ctx = zlog.ContextWithValues(ctx, "component", "notifier/Processor.create")
	zlog.Debug(ctx).
		Stringer("prev", prev).
		Stringer("cur", e.uo.Ref).
		Msg("retrieving diff")
	diff, err := p.matcher.UpdateDiff(ctx, prev, e.uo.Ref)
	if err != nil {
		return fmt.Errorf("failed to get update diff: %v", err)
	}
	zlog.Debug(ctx).
		Int("removed", len(diff.Removed)).
		Int("added", len(diff.Added)).
		Msg("diff results")

	tab := notifTab{
		N:      make([]Notification, 0),
		lookup: make(map[string]int),
	}
	eg, wctx := errgroup.WithContext(ctx)
	eg.Go(getAffected(wctx, p.indexer, p.NoSummary, diff.Added, Added, &tab))
	eg.Go(getAffected(wctx, p.indexer, p.NoSummary, diff.Removed, Removed, &tab))
	if err := eg.Wait(); err != nil {
		return fmt.Errorf("failed to get affected manifests: %v", err)
	}

	// Don't count up the affected manifests unless we're going to print it.
	if ev := zlog.Debug(ctx); ev.Enabled() {
		var added, removed int
		for _, n := range tab.N {
			switch n.Reason {
			case Added:
				added++
			case Removed:
				removed++
			}
		}
		ev.
			Int("added", added).
			Int("removed", removed).
			Msg("affected manifest counts")
	}

	if len(tab.N) == 0 {
		// directly add a "delivered" receipt, this will stop subsequent processing
		// of this update operation and also avoid delivery attempts.
		r := Receipt{
			NotificationID: uuid.New(),
			UOID:           e.uo.Ref,
			Status:         Delivered,
		}
		zlog.Debug(ctx).
			Msg("no affected manifests for update operation, setting to delivered.")
		err := p.store.PutReceipt(ctx, e.uo.Updater, r)
		if err != nil {
			return fmt.Errorf("failed to put receipt: %v", err)
		}
		return nil
	}

	opts := PutOpts{
		Updater:        e.updater,
		UpdateID:       e.uo.Ref,
		NotificationID: uuid.New(),
		Notifications:  tab.N,
	}
	err = p.store.PutNotifications(ctx, opts)
	if err != nil {
		return fmt.Errorf("failed to store notifications: %v", err)
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// NotifTab is a handle for a slice of Notifications.
//
// It has supporting structures for concurrent use and summaries.
type notifTab struct {
	sync.Mutex
	lookup map[string]int // only used in "summary" mode
	N      []Notification
}

// GetAffected issues AffectedManifest calls in chunks and merges the result.
//
// Its signature is weird to make use in an errgroup a little bit nicer.
func getAffected(ctx context.Context, ic indexer.Service, nosummary bool, vs []claircore.Vulnerability, r Reason, out *notifTab) func() error {
	const chunk = 1000
	return func() error {
		var s []claircore.Vulnerability
		for len(vs) > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			s = vs[:min(chunk, len(vs))]
			vs = vs[len(s):]
			a, err := ic.AffectedManifests(ctx, s)
			if err != nil {
				return err
			}
			for manifest, vulns := range a.VulnerableManifests {
				digest, err := claircore.ParseDigest(manifest)
				if err != nil {
					return err
				}
				// The vulns slice is sorted most severe to lease severe, so
				// when in summary mode, we only need to check the initial vuln.
				if !nosummary {
					vuln := a.Vulnerabilities[vulns[0]]
					key := digest.String()
					var n *Notification
					out.Lock()
					// First, lookup if there's a notification for this
					// manifest.
					i, ok := out.lookup[key]
					if ok {
						n = &out.N[i]
					}
					if n == nil {
						// If this is the first appearance of this manifest,
						// insert it.
						i := len(out.N)
						out.N = append(out.N, Notification{
							Manifest: digest,
							Reason:   r,
						})
						out.lookup[key] = i
						n = &out.N[i]
						n.Vulnerability.FromVulnerability(vuln)
					} else {
						// If we've seen this before, check the severity and
						// swap if the new vuln is more severe.
						var sev claircore.Severity
						if err := sev.UnmarshalText([]byte(n.Vulnerability.Severity)); err != nil {
							out.Unlock()
							return err
						}
						if sev < vuln.NormalizedSeverity {
							n.Vulnerability.FromVulnerability(vuln)
						}
					}
					out.Unlock()
					continue
				}
				// If not in summary, create all the notifications.
				for idx := range vulns {
					vuln := a.Vulnerabilities[vulns[idx]]
					out.Lock()
					i := len(out.N)
					out.N = append(out.N, Notification{
						Manifest: digest,
						Reason:   r,
					})
					n := &out.N[i]
					n.Vulnerability.FromVulnerability(vuln)
					out.Unlock()
				}
			}
		}
		return nil
	}
}

// safe guards against situations where creating notifications is
// incorrect.
//
// if deemed safe to create notifications the previous update operation will be
// returned
//
// will be performed under a distributed lock.
func (p *Processor) safe(ctx context.Context, e Event) (bool, uuid.UUID) {
	ctx = zlog.ContextWithValues(ctx, "component", "notifier/Processor.safe")

	// confirm we are not making duplicate notifications
	var errNoReceipt *clairerror.ErrNoReceipt
	_, err := p.store.ReceiptByUOID(ctx, e.uo.Ref)
	switch {
	case errors.As(err, &errNoReceipt):
		// hop out of switch
	case err != nil:
		zlog.Error(ctx).
			Err(err).
			Msg("received error getting receipt by UOID")
		return false, uuid.Nil
	default:
		zlog.Info(ctx).
			Msg("receipt created by another processor. will not process notifications")
		return false, uuid.Nil
	}

	// confirm UOID is not stale and get previous UOID for diffing if exists.
	// if no previous UOID, return false, we don't want a full diff of notifications
	// TODO(louis) UpdateOperations signature supports getting "all" for a given updater
	// but code path is not implemented. implement this to optimize.
	all, err := p.matcher.UpdateOperations(ctx, driver.VulnerabilityKind)
	if err != nil {
		zlog.Error(ctx).
			Err(err).
			Msg("received error getting update operations from matcher")
		return false, uuid.Nil
	}
	if _, ok := all[e.updater]; !ok {
		zlog.Warn(ctx).
			Msg("updater missing from update operations returned from matcher. matcher may have garbage collected")
		return false, uuid.Nil
	}

	uos := all[e.updater]

	var current driver.UpdateOperation
	var prev driver.UpdateOperation

	if len(uos) == 1 {
		current = uos[0]
		prev.Ref = uuid.Nil
	} else {
		current, prev = uos[0], uos[1]
	}

	if current.Ref.String() != e.uo.Ref.String() {
		zlog.Info(ctx).
			Stringer("new", current.Ref).
			Msg("newer update operation is present, will not process notifications")
		return false, uuid.Nil
	}
	return true, prev.Ref
}
