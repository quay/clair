package postgres

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/quay/claircore"
	cctest "github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/zlog"

	"github.com/quay/clair/v4/notifier"
)

// TestE2E performs an end to end test ensuring creating, retrieving,
// bookkeeping, and deleting of notifications and associated data works
// correctly.
func TestE2E(t *testing.T) {
	integration.NeedDB(t)
	ctx := zlog.Test(context.Background(), t)
	for _, e := range []*e2e{
		NewE2E(ctx, t, 1),
		NewE2E(ctx, t, 10),
		NewE2E(ctx, t, 100),
	} {
		t.Run(strconv.Itoa(len(e.notifications)), func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			e.Run(ctx, t)
		})
	}
}

// e2e is a series of test cases for handling notification
// persistence.
//
// each method on e2e fulfills the expected function signature
// for t.Run() and is thus eligible to be used as a sub-test.
//
// e2e.Run drives the subtest order and will fail on first subtest
// failure
type e2e struct {
	// the updater associated with the set of notifications under test
	updater string
	// a store instance implementing notification persistence methods
	store *Store
	// the notifications this test persist and retrieves
	notifications []notifier.Notification
	// the notification ID this e2e test will use
	notificationID uuid.UUID
	// the update operation ID associated with the set of notifications under test
	updateID uuid.UUID
}

func NewE2E(ctx context.Context, t *testing.T, ct int) *e2e {
	updater := fmt.Sprintf("%s-%d", t.Name(), ct)
	id := uuid.New()
	vs := cctest.GenUniqueVulnerabilities(ct, updater)
	ns := make([]notifier.Notification, len(vs))
	for i, v := range vs {
		n := &ns[i]
		n.Manifest = cctest.RandomSHA256Digest(t)
		switch rand.Intn(3) {
		case 0:
			n.Reason = notifier.Added
		case 1:
			n.Reason = notifier.Changed
		case 2:
			n.Reason = notifier.Removed
		}
		n.Vulnerability.FromVulnerability(v)
	}
	e := e2e{
		notificationID: id,
		updater:        updater,
		updateID:       uuid.New(),
		notifications:  ns,
	}
	return &e
}

func (e *e2e) Run(ctx context.Context, t *testing.T) {
	e.store = TestingStore(ctx, t)
	type subtest struct {
		do   func(context.Context) func(t *testing.T)
		name string
	}
	for _, sub := range [...]subtest{
		{name: "PutNotifications", do: e.PutNotifications},
		{name: "Created", do: e.Created},
		{name: "Notifications", do: e.Notifcations},
		{name: "SetDelivered", do: e.SetDelivered},
		{name: "SetDeliveryFailed", do: e.SetDeliveryFailed},
		{name: "SetDeleted", do: e.SetDeleted},
		{name: "PutReceipt", do: e.PutReceipt},
		{name: "CollectNotifications", do: e.CollectNotifications},
	} {
		t.Run(sub.name, sub.do(ctx))
		if t.Failed() {
			t.FailNow()
		}
	}
}

// PutNotifications adds a set of notifications to the database and confirms no
// error occurs.
func (e *e2e) PutNotifications(ctx context.Context) func(*testing.T) {
	return func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		opts := notifier.PutOpts{
			Updater:        e.updater,
			NotificationID: e.notificationID,
			Notifications:  e.notifications,
			UpdateID:       e.updateID,
		}
		if err := e.store.PutNotifications(ctx, opts); err != nil {
			t.Error(err)
		}
	}
}

// Created ensures the expected notification ID is returned when persistence
// layer is queried for all created, a specific receipt, or a receipt by UOID.
func (e *e2e) Created(ctx context.Context) func(*testing.T) {
	return func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		ids, err := e.store.Created(ctx)
		if err != nil {
			t.Error(err)
		}
		if got, want := len(ids), 1; got != want {
			t.Errorf("got: %d, want: %d", got, want)
		}
		want := e.notificationID
		if got := ids[0]; !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}

		r, err := e.store.Receipt(ctx, want)
		if err != nil {
			t.Error(err)
		}
		if got := r.NotificationID; !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
		if got, want := r.Status, notifier.Created; !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}

		r, err = e.store.ReceiptByUOID(ctx, e.updateID)
		if err != nil {
			t.Error(err)
		}
		if got := r.NotificationID; !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
		if got, want := r.Status, notifier.Created; !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
	}
}

// Notifications confirms the correct notifications were returned from the
// database when providing the notification ID.
func (e *e2e) Notifcations(ctx context.Context) func(*testing.T) {
	return func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		want := e.notificationID
		inner := func(p *notifier.Page) func(*testing.T) {
			return func(t *testing.T) {
				ctx := zlog.Test(ctx, t)
				var ns []notifier.Notification
				for {
					rs, np, err := e.store.Notifications(ctx, want, p)
					if err != nil {
						t.Error(err)
					}
					ns = append(ns, rs...)
					if np.Next == nil {
						break
					}
					p = &np
				}
				if got, want := len(ns), len(e.notifications); got != want {
					t.Errorf("got: %d, want: %d", got, want)
				}
				opts := cmp.Options{
					cmpopts.IgnoreUnexported(claircore.Digest{}),
					cmpopts.IgnoreFields(claircore.Vulnerability{}, "ID"),
					cmp.Transformer("Sort", func(in []notifier.Notification) []notifier.Notification {
						out := make([]notifier.Notification, len(in))
						copy(out, in)
						sort.Slice(out, func(i, j int) bool {
							return out[i].ID.String() < out[j].ID.String()
						})
						return out
					}),
				}
				if got, want := ns, e.notifications; !cmp.Equal(got, want, opts) {
					t.Error(cmp.Diff(got, want, opts))
				}
			}
		}
		t.Run("NilPage", inner(nil))
		t.Run("5Page", inner(&notifier.Page{Size: 5}))
		t.Run("500Page", inner(&notifier.Page{Size: 500}))
	}
}

// SetDelivered confirms a receipt for a notification ID can be set to
// delivered.
func (e *e2e) SetDelivered(ctx context.Context) func(*testing.T) {
	return func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		want := e.notificationID
		err := e.store.SetDelivered(ctx, want)
		if err != nil {
			t.Error(err)
		}
		receipt, err := e.store.Receipt(ctx, want)
		if err != nil {
			t.Error(err)
		}
		if got := receipt.NotificationID; !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
		if got, want := receipt.Status, notifier.Delivered; !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
	}
}

// SetDeliveryFailed confirms a receipt for a notification ID can be set to
// delivered.
func (e *e2e) SetDeliveryFailed(ctx context.Context) func(*testing.T) {
	return func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		want := e.notificationID
		err := e.store.SetDeliveryFailed(ctx, want)
		if err != nil {
			t.Error(err)
		}
		receipt, err := e.store.Receipt(ctx, e.notificationID)
		if err != nil {
			t.Error(err)
		}
		if got := receipt.NotificationID; !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
		if got, want := receipt.Status, notifier.DeliveryFailed; !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
		ids, err := e.store.Failed(ctx)
		if err != nil {
			t.Error(err)
		}
		if got, want := len(ids), 1; got != want {
			t.Errorf("got: %d, want: %d", got, want)
		}
		if got := ids[0]; !cmp.Equal(got, want) {
			t.Errorf(cmp.Diff(got, want))
		}
	}
}

// SetDeleted ...
func (e *e2e) SetDeleted(ctx context.Context) func(*testing.T) {
	return func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		want := e.notificationID
		err := e.store.SetDeleted(ctx, want)
		if err != nil {
			t.Error(err)
		}
		receipt, err := e.store.Receipt(ctx, want)
		if err != nil {
			t.Error(err)
		}
		if got := receipt.NotificationID; !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
		if got, want := receipt.Status, notifier.Deleted; !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
		ids, err := e.store.Deleted(ctx)
		if err != nil {
			t.Error(err)
		}
		if got, want := len(ids), 1; got != want {
			t.Errorf("got: %d, want: %d", got, want)
		}
		if got := ids[0]; !cmp.Equal(got, want) {
			t.Errorf(cmp.Diff(got, want))
		}
	}
}

// PutReceipt will confirm a receipt can be directly placed into the database.
func (e *e2e) PutReceipt(ctx context.Context) func(*testing.T) {
	return func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		want := notifier.Receipt{
			NotificationID: uuid.New(),
			UOID:           uuid.New(),
			Status:         notifier.Delivered,
		}
		err := e.store.PutReceipt(ctx, "test-updater", want)
		if err != nil {
			t.Fatalf("failed to put receipt: %v", err)
		}

		got, err := e.store.Receipt(ctx, want.NotificationID)
		if err != nil {
			t.Error(err)
		}
		if !cmp.Equal(got, want, cmpopts.IgnoreFields(got, "TS")) {
			t.Error(cmp.Diff(got, want))
		}

		got, err = e.store.ReceiptByUOID(ctx, want.UOID)
		if err != nil {
			t.Error(err)
		}
		if !cmp.Equal(got, want, cmpopts.IgnoreFields(got, "TS")) {
			t.Error(cmp.Diff(got, want))
		}
	}
}

func (e *e2e) CollectNotifications(ctx context.Context) func(*testing.T) {
	const jump = `UPDATE receipt SET ts = (CURRENT_TIMESTAMP - INTERVAL '21 days') WHERE notification_id = $1;`
	return func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		pool := e.store.pool
		// Jump our receipt back in time.
		if _, err := pool.Exec(ctx, jump, e.notificationID); err != nil {
			t.Error(err)
		}

		if err := e.store.CollectNotifications(ctx); err != nil {
			t.Error(err)
		}

		var ct int
		if err := pool.QueryRow(ctx, `SELECT COUNT(id) FROM notification_body;`).Scan(&ct); err != nil {
			t.Error(err)
		}
		if got, want := ct, 0; got != want {
			t.Errorf("got: %d row remaining, wanted: %d rows remaining", got, want)
		}
	}
}
