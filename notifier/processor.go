package notifier

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/distlock"
	"github.com/rs/zerolog"
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
	// NoSummary controls whether per-manifest vulnerability summarization
	// should happen.
	NoSummary bool
	// NoSummary is a little awkward to use, but reversing the boolean this way
	// makes the defaults line up better.

	// distributed lock used for mutual exclusion
	distLock distlock.Locker
	// a handle to an indexer service
	indexer indexer.Service
	// a handle to a matcher service
	matcher matcher.Service
	// a store instance to persist notifications
	store Store
	// a integer id used for logging
	id uint8
}

func NewProcessor(id int, distLock distlock.Locker, indexer indexer.Service, matcher matcher.Service, store Store) *Processor {
	return &Processor{
		distLock: distLock,
		indexer:  indexer,
		matcher:  matcher,
		store:    store,
		id:       uint8(id),
	}
}

// Process is an async method which receives new UOs as events,
// creates notifications, persists these notifications,
// and updates the notifier system with the "latest" seen UOID.
//
// Canceling the ctx will end the processing.
func (p *Processor) Process(ctx context.Context, c <-chan Event) {
	go p.process(ctx, c)
}

// process is intended to be ran as a go routine.
//
// implements the blocking event loop of a processor.
func (p *Processor) process(ctx context.Context, c <-chan Event) {
	log := zerolog.Ctx(ctx).With().
		Uint8("processor_id", p.id).
		Str("component", "notifier/processor/Processor.process").Logger()

	log.Debug().Msg("processing events")
	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("context canceled: ending event processing")
		case e := <-c:
			uoid := e.uo.Ref.String()
			log := zerolog.Ctx(ctx).With().
				Str("component", "notifier/processor/Processor.process").
				Str("updater", e.updater).
				Str("UOID", uoid).
				Uint8("processor_id", p.id).
				Logger()
			log.Debug().Msg("processing")
			locked, err := p.distLock.TryLock(ctx, uoid)
			if err != nil {
				log.Error().Err(err).Msg("received error trying lock. backing off till next UOID")
				continue
			}
			if !locked {
				log.Debug().Msg("lock acquired by another processor. will not process")
				continue
			}
			// function used to schedule unlock via defer
			err = func() error {
				defer p.distLock.Unlock()
				safe, prev := p.safe(ctx, e)
				if !safe {
					return nil
				}
				return p.create(ctx, e, prev)
			}()
			if err != nil {
				log.Error().Err(err).Msg("failed to create notifications")
			}
		}
	}
}

// create implements the business logic of creating and persisting
// notifications
//
// will be performed under a distributed lock
func (p *Processor) create(ctx context.Context, e Event, prev uuid.UUID) error {
	uoid := e.uo.Ref.String()
	log := zerolog.Ctx(ctx).With().
		Uint8("processor_id", p.id).
		Str("component", "notifier/processor/Processor.create").
		Str("updater", e.updater).
		Str("UOID", uoid).
		Logger()
	log.Debug().Str("prev", prev.String()).Str("cur", uoid).Msg("retrieving diff")
	diff, err := p.matcher.UpdateDiff(ctx, prev, e.uo.Ref)
	if err != nil {
		return fmt.Errorf("failed to get update diff: %v", err)
	}
	log.Debug().Int("removed", len(diff.Removed)).Int("added", len(diff.Added)).Msg("diff results")

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
	if ev := log.Debug(); ev.Enabled() {
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
		log.Debug().Str("update_operation", e.uo.Ref.String()).Msg("no affected manifests for update operation, setting to delivered.")
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
	N      []Notification
	lookup map[string]int // only used in "summary" mode
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
	uoid := e.uo.Ref.String()
	log := zerolog.Ctx(ctx).With().
		Uint8("processor_id", p.id).
		Str("component", "notifier/processor/Processor.Process").
		Str("updater", e.updater).
		Str("UOID", uoid).
		Logger()

	// confirm we are not making duplicate notifications
	var errNoReceipt clairerror.ErrNoReceipt
	_, err := p.store.ReceiptByUOID(ctx, e.uo.Ref)
	switch {
	case errors.As(err, &errNoReceipt):
		// hop out of switch
	case err != nil:
		log.Error().Err(err).Msg("received error getting receipt by UOID")
		return false, uuid.Nil
	default:
		log.Info().Msg("receipt created by another processor. will not process notifications")
		return false, uuid.Nil
	}

	// confirm UOID is not stale and get previous UOID for diffing if exists.
	// if no previous UOID, return false, we don't want a full diff of notifications
	// TODO(louis) UpdateOperations signature supports getting "all" for a given updater
	// but code path is not implemented. implement this to optimize.
	all, err := p.matcher.UpdateOperations(ctx)
	if err != nil {
		log.Error().Err(err).Msg("received error getting update operations from matcher")
		return false, uuid.Nil
	}
	if _, ok := all[e.updater]; !ok {
		log.Warn().Msg("updater missing from update operations returned from matcher. matcher may have garbage collected")
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
		log.Info().Str("new", current.Ref.String()).Msg("newer update operation is present, will not process notifications")
		return false, uuid.Nil
	}
	return true, prev.Ref
}
