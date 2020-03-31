package postgres

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/quay/clair/v4/notifier"
	"github.com/quay/claircore"
	cctest "github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
)

const (
	updater = "updater"
)

// TestE2E performs an end to end test ensuring creating,
// retreiving, bookkeeping, and deleting of notifications
// and asssociated data works correctly
func TestE2E(t *testing.T) {
	integration.Skip(t)
	digest, _ := claircore.ParseDigest("sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a")
	notificationID := uuid.New()
	// this function puts a single noification undertest
	vuln, vsummary := cctest.GenUniqueVulnerabilities(1, updater)[0], notifier.VulnSummary{}
	vsummary.FromVulnerability(*vuln)
	notifications := []notifier.Notification{
		{
			Manifest:      digest,
			Reason:        "added",
			Vulnerability: vsummary,
		},
	}
	ctx := context.Background()
	db, store, teardown := TestStore(ctx, t)
	defer teardown()
	e := e2e{
		notificaitonID: notificationID,
		updater:        updater,
		updateID:       uuid.New(),
		notification:   notifications[0],
		db:             db,
		store:          store,
		ctx:            ctx,
	}
	t.Run("notifications e2e", e.Run)
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
	// the notification ID this e2e test will use
	notificaitonID uuid.UUID
	// the updater associated with the set of notifications under test
	updater string
	// the update operation ID associated with the set of notifications under test
	updateID uuid.UUID
	// the notification this test persist and retrieves
	notification notifier.Notification
	// whether any of the tests have failed
	failed bool
	// a sqldb instance to the test database
	db *sqlx.DB
	// a store instance implementing notification persistence methods
	store *Store
	// root ctx tests may derive off
	ctx context.Context
}

// Run drives the series of sub-tests
// Run will report the first subtest that fails.
func (e *e2e) Run(t *testing.T) {
	type subtest struct {
		name string
		do   func(t *testing.T)
	}
	subtests := [...]subtest{
		{"PutNotifications", e.PutNotifications},
		{"Created", e.Created},
		{"Notifications", e.Notifcations},
		{"SetDelivered", e.SetDelivered},
		{"SetDeliveryFailed", e.SetDeliveryFailed},
		{"SetDeleted", e.SetDeleted},
	}
	for i := range subtests {
		subtest := subtests[i]
		t.Run(subtest.name, subtest.do)
		if e.failed {
			t.FailNow()
		}
	}
}

// PutNotifications adds a set of notifications to the database
// and confims no error occurs
func (e *e2e) PutNotifications(t *testing.T) {
	defer func() {
		e.failed = t.Failed()
	}()
	opts := notifier.PutOpts{
		Updater:        e.updater,
		NotificationID: e.notificaitonID,
		Notifications:  []notifier.Notification{e.notification},
		UpdateID:       e.updateID,
	}
	err := e.store.PutNotifications(e.ctx, opts)
	if err != nil {
		t.Fatalf("failed to put notifications: %v", err)
	}
}

// Created ensures the expected notification id is returned
// when persistence layer is queried for all created,
// a specific receipt, or a receipt by UOID
func (e *e2e) Created(t *testing.T) {
	defer func() {
		e.failed = t.Failed()
	}()
	ids, err := e.store.Created(e.ctx)
	if err != nil {
		t.Fatalf("failed to retrieve created notification ids: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("expected a single notification id. got: %v", ids)
	}
	if !cmp.Equal(ids[0], e.notificaitonID) {
		t.Fatalf(cmp.Diff(ids[0], e.notificaitonID))
	}

	receipt, err := e.store.Receipt(e.ctx, e.notificaitonID)
	if err != nil {
		t.Fatalf("failed to retrieve receipt by notification id")
	}
	if !cmp.Equal(receipt.NotificationID, e.notificaitonID) {
		t.Fatal(cmp.Diff(receipt.NotificationID, e.notificaitonID))
	}
	if !cmp.Equal(receipt.Status, notifier.Created) {
		t.Fatal(cmp.Diff(receipt.Status, notifier.Delivered))
	}

	receipt, err = e.store.ReceiptByUOID(e.ctx, e.updateID)
	if err != nil {
		t.Fatalf("failed to retrieve receipt by OUID")
	}
	if !cmp.Equal(receipt.NotificationID, e.notificaitonID) {
		t.Fatal(cmp.Diff(receipt.NotificationID, e.notificaitonID))
	}
	if !cmp.Equal(receipt.Status, notifier.Created) {
		t.Fatal(cmp.Diff(receipt.Status, notifier.Delivered))
	}
}

// Notifications confirms the correct notifications were returned
// from the database when providing the notification id
func (e *e2e) Notifcations(t *testing.T) {
	defer func() {
		e.failed = t.Failed()
	}()
	notifications, _, err := e.store.Notifications(e.ctx, e.notificaitonID, nil)
	if err != nil {
		t.Fatalf("failed to retrieve persisted notification: %v", err)
	}
	if len(notifications) != 1 {
		t.Fatalf("expected a single notifcation to be returned for notification id %v but received %d", e.notificaitonID, len(notifications))
	}
	opts := cmpopts.IgnoreUnexported(claircore.Digest{})
	if !cmp.Equal(notifications[0].Manifest, e.notification.Manifest, opts) {
		t.Fatal(cmp.Diff(notifications[0].Manifest, e.notification.Manifest))
	}
	if !cmp.Equal(notifications[0].Reason, e.notification.Reason) {
		t.Fatal(cmp.Diff(notifications[0].Reason, e.notification.Reason))
	}
	opts = cmpopts.IgnoreFields(claircore.Vulnerability{}, "ID")
	if !cmp.Equal(notifications[0].Vulnerability, e.notification.Vulnerability, opts) {
		t.Fatal(cmp.Diff(notifications[0].Vulnerability, e.notification.Vulnerability))
	}
}

// SetDelivered confirms a receipt for a notification id
// can be set to delivered
func (e *e2e) SetDelivered(t *testing.T) {
	defer func() {
		e.failed = t.Failed()
	}()
	err := e.store.SetDelivered(e.ctx, e.notificaitonID)
	if err != nil {
		t.Fatalf("failed to set notification receipt to delivered")
	}
	receipt, err := e.store.Receipt(e.ctx, e.notificaitonID)
	if err != nil {
		t.Fatalf("failed to retrieve receipt after setting it's status to delivered")
	}
	if !cmp.Equal(receipt.NotificationID, e.notificaitonID) {
		t.Fatal(cmp.Diff(receipt.NotificationID, e.notificaitonID))
	}
	if !cmp.Equal(receipt.Status, notifier.Delivered) {
		t.Fatal(cmp.Diff(receipt.Status, notifier.Delivered))
	}
}

// SetDeliveryFailed confirms a receipt for a notification id
// can be set to delivered
func (e *e2e) SetDeliveryFailed(t *testing.T) {
	defer func() {
		e.failed = t.Failed()
	}()
	err := e.store.SetDeliveryFailed(e.ctx, e.notificaitonID)
	if err != nil {
		t.Fatalf("failed to set notification receipt to delivered")
	}
	receipt, err := e.store.Receipt(e.ctx, e.notificaitonID)
	if err != nil {
		t.Fatalf("failed to retrieve receipt after setting it's status to delete")
	}
	if !cmp.Equal(receipt.NotificationID, e.notificaitonID) {
		t.Fatal(cmp.Diff(receipt.NotificationID, e.notificaitonID))
	}
	if !cmp.Equal(receipt.Status, notifier.DeliveryFailed) {
		t.Fatal(cmp.Diff(receipt.Status, notifier.DeliveryFailed))
	}
	ids, err := e.store.Failed(e.ctx)
	if err != nil {
		t.Fatalf("failed to retrieve created notification ids: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("expected a single notification id. got: %v", ids)
	}
	if !cmp.Equal(ids[0], e.notificaitonID) {
		t.Fatalf(cmp.Diff(ids[0], e.notificaitonID))
	}

}

// SetDeliveryFailed confirms a receipt for a notification id
// can be set to delivered
func (e *e2e) SetDeleted(t *testing.T) {
	defer func() {
		e.failed = t.Failed()
	}()
	err := e.store.SetDeleted(e.ctx, e.notificaitonID)
	if err != nil {
		t.Fatalf("failed to set notification receipt to delivered")
	}
	receipt, err := e.store.Receipt(e.ctx, e.notificaitonID)
	if err != nil {
		t.Fatalf("failed to retrieve receipt after setting it's status to delete")
	}
	if !cmp.Equal(receipt.NotificationID, e.notificaitonID) {
		t.Fatal(cmp.Diff(receipt.NotificationID, e.notificaitonID))
	}
	if !cmp.Equal(receipt.Status, notifier.Deleted) {
		t.Fatal(cmp.Diff(receipt.Status, notifier.Deleted))
	}
}
