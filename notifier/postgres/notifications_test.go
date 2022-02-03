package postgres

import (
	"context"
	"errors"
	"math/rand"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/zlog"

	"github.com/quay/clair/v4/notifier"
)

func TestNotificationCopy(t *testing.T) {
	integration.NeedDB(t)
	ctx := zlog.Test(context.Background(), t)
	for _, tc := range []notificationCopyTestcase{
		{Count: 1},
		{Count: 10},
		{Count: 100},
		{Count: 1000},
		{Count: 10000},
	} {
		tc.Setup(t)
		t.Run(strconv.Itoa(tc.Count), tc.Func(ctx))
	}
}

type notificationCopyTestcase struct {
	Notifications []notifier.Notification
	Count         int
}

func (n *notificationCopyTestcase) Setup(t testing.TB) {
	vs := test.GenUniqueVulnerabilities(n.Count, t.Name())
	ns := make([]notifier.Notification, len(vs))
	for i := range vs {
		n := &ns[i]
		n.Manifest = test.RandomSHA256Digest(t)
		switch rand.Intn(3) {
		case 0:
			n.Reason = notifier.Added
		case 1:
			n.Reason = notifier.Changed
		case 2:
			n.Reason = notifier.Removed
		}
		n.Vulnerability.FromVulnerability(vs[i])
	}
	n.Notifications = ns
}

func (n notificationCopyTestcase) Func(ctx context.Context) func(*testing.T) {
	id := uuid.New()
	return func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		n.Setup(t)
		src := copyNotifications(&id, n.Notifications)
		s := TestingStore(ctx, t)
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			t.Error(err)
		}
		defer func() {
			if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
				t.Error(err)
			}
		}()
		tag, err := tx.Exec(ctx, `INSERT INTO notification (id) VALUES ($1);`, id)
		if err != nil {
			t.Error(err)
		}
		if got, want := int(tag.RowsAffected()), 1; got != want {
			t.Errorf("got: %d, want: %d", got, want)
		}
		ct, err := tx.CopyFrom(ctx, pgx.Identifier{"notification_body"}, src.Columns(), src)
		if err != nil {
			t.Error(err)
		}
		if got, want := int(ct), len(n.Notifications); got != want {
			t.Errorf("got: %d, want: %d", got, want)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Error(err)
		}
	}
}
