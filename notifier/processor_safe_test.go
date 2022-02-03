package notifier

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/zlog"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/matcher"
)

var (
	testUpdater        = "test-updater"
	start              = time.Now()
	processorUpdateOps = map[string][]driver.UpdateOperation{
		// the array will be sorted by newest UO
		testUpdater: []driver.UpdateOperation{
			{
				Ref:         uuid.New(),
				Date:        start,
				Fingerprint: "fp",
				Updater:     testUpdater,
			},
			{
				Ref:         uuid.New(),
				Date:        start.Add(-10 * time.Minute),
				Fingerprint: "fp",
				Updater:     testUpdater,
			},
		},
	}
)

// TestProcessSafe is a harness for running concurrent tests which ensure notification
// creation happens safely.
func TestProcessorSafe(t *testing.T) {
	t.Run("UnsafeDuplications", testUnsafeDuplications)
	t.Run("UnsafeStaleUOID", testUnsafeStaleUOID)
	t.Run("UnsafeMatcherErr", testUnsafeMatcherErr)
	t.Run("UnsafeStoreErr", testUnsafeStoreErr)
	t.Run("Safe", testSafe)
}

// testSafe confirms when all safety guards pass the processor will
// create notifications.
func testSafe(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	sm := &MockStore{
		ReceiptByUOID_: func(ctx context.Context, id uuid.UUID) (Receipt, error) {
			return Receipt{}, &clairerror.ErrNoReceipt{}
		},
	}
	mm := &matcher.Mock{
		UpdateOperations_: func(context.Context, driver.UpdateKind, ...string) (map[string][]driver.UpdateOperation, error) {
			return processorUpdateOps, nil
		},
	}
	p := Processor{
		store:   sm,
		matcher: mm,
	}
	e := Event{
		updater: testUpdater,
		uo:      processorUpdateOps[testUpdater][0],
	}
	b, _ := p.safe(ctx, e)
	if !b {
		t.Fatalf("got: %v, want: %v", b, true)
	}
}

// testUnsafeStoreErr confirms notifications will not be created if Store is returning an error.
func testUnsafeStoreErr(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	sm := &MockStore{
		ReceiptByUOID_: func(ctx context.Context, id uuid.UUID) (Receipt, error) {
			return Receipt{}, fmt.Errorf("expected")
		},
	}
	mm := &matcher.Mock{
		UpdateOperations_: func(context.Context, driver.UpdateKind, ...string) (map[string][]driver.UpdateOperation, error) {
			return processorUpdateOps, nil
		},
	}

	p := Processor{
		store:   sm,
		matcher: mm,
	}

	e := Event{
		updater: testUpdater,
		uo:      processorUpdateOps[testUpdater][0],
	}
	b, _ := p.safe(ctx, e)
	if b {
		t.Fatalf("got: %v, want: %v", b, false)
	}
}

// testUnsafeMatcherErr confirms notifications will not be created if Matcher is returning an error.
func testUnsafeMatcherErr(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	sm := &MockStore{
		ReceiptByUOID_: func(ctx context.Context, id uuid.UUID) (Receipt, error) {
			return Receipt{}, &clairerror.ErrNoReceipt{}
		},
	}
	mm := &matcher.Mock{
		UpdateOperations_: func(context.Context, driver.UpdateKind, ...string) (map[string][]driver.UpdateOperation, error) {
			return processorUpdateOps, fmt.Errorf("expected")
		},
	}

	p := Processor{
		store:   sm,
		matcher: mm,
	}

	e := Event{
		updater: testUpdater,
		uo:      processorUpdateOps[testUpdater][0],
	}
	b, _ := p.safe(ctx, e)
	if b {
		t.Fatalf("got: %v, want: %v", b, false)
	}
}

// testSafeStaleUOID confirms the guard against creating stale notifications
// works correctly.
func testUnsafeStaleUOID(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	sm := &MockStore{
		ReceiptByUOID_: func(ctx context.Context, id uuid.UUID) (Receipt, error) {
			return Receipt{}, &clairerror.ErrNoReceipt{}
		},
	}
	mm := &matcher.Mock{
		UpdateOperations_: func(context.Context, driver.UpdateKind, ...string) (map[string][]driver.UpdateOperation, error) {
			return processorUpdateOps, nil
		},
	}

	p := Processor{
		store:   sm,
		matcher: mm,
	}

	e := Event{
		updater: testUpdater,
		uo:      processorUpdateOps[testUpdater][1],
	}

	b, _ := p.safe(ctx, e)
	if b {
		t.Fatalf("got: %v, want: %v", b, false)
	}
}

// testSafeDuplications confirms the guard against creating
// duplicate notifications works correctly.
func testUnsafeDuplications(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	sm := &MockStore{
		ReceiptByUOID_: func(ctx context.Context, id uuid.UUID) (Receipt, error) {
			return Receipt{}, nil
		},
	}
	mm := &matcher.Mock{
		UpdateOperations_: func(context.Context, driver.UpdateKind, ...string) (map[string][]driver.UpdateOperation, error) {
			return processorUpdateOps, nil
		},
	}

	p := Processor{
		store:   sm,
		matcher: mm,
	}

	e := Event{
		updater: testUpdater,
		uo:      processorUpdateOps[testUpdater][0],
	}
	b, _ := p.safe(ctx, e)
	if b {
		t.Fatalf("got: %v, want: %v", b, false)
	}
}
