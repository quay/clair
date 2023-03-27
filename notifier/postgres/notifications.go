package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/notifier"
	"github.com/quay/zlog"
)

var (
	notificationsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "notifications_total",
			Help:      "Total number of database queries issued in the notifications method",
		},
		[]string{"query", "error"},
	)
	notificationsDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "notifications_duration_seconds",
			Help:      "Duration of all queries issued in the notifications method",
		},
		[]string{"query", "error"},
	)

	gcNotificationCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "collectnotification_query_total",
			Help:      "Total number of database queries issued in the CollectNotification method",
		},
		[]string{"query", "error"},
	)
	gcNotificationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "collectnotification_duration_seconds",
			Help:      "Duration of all queries issued in the CollectNotification method",
		},
		[]string{"query", "error"},
	)
	gcNotificationAffected = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "collectnotification_affected_total",
			Help:      "Total number of rows affected in the CollectNotification method",
		},
		[]string{"query", "error"},
	)

	putNotificationsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "putnotifications_query_total",
			Help:      "Total number of database queries issued in the PutNotifications method",
		},
		[]string{"query", "error"},
	)
	putNotificationsDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "putnotifications_duration_seconds",
			Help:      "Duration of all queries issued in the PutNotifications method",
		},
		[]string{"query", "error"},
	)
	putNotificationsAffected = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "putnotifications_affected_total",
			Help:      "Total number of rows affected in the PutNotifications method",
		},
		[]string{"query", "error"},
	)
)

// Notifications retrieves the list of notifications associated with a
// notification ID.
func (s *Store) Notifications(ctx context.Context, id uuid.UUID, page *notifier.Page) ([]notifier.Notification, notifier.Page, error) {
	const (
		query      = "SELECT id, body FROM notification_body WHERE notification_id = $1::uuid"
		pagedQuery = "SELECT id, body FROM notification_body WHERE notification_id = $1::uuid AND id > $2 ORDER BY id ASC LIMIT $3"
	)

	// If no page argument, early return all notifications.
	if page == nil {
		p := notifier.Page{}
		ns := make([]notifier.Notification, 0)
		err := s.pool.AcquireFunc(ctx, func(c *pgxpool.Conn) error {
			var err error
			timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
				notificationsDuration.WithLabelValues(`query`, errLabel(err)).Observe(v)
			}))
			defer timer.ObserveDuration()
			var rows pgx.Rows
			rows, err = c.Query(ctx, query, id)
			notificationsCounter.WithLabelValues(`query`, errLabel(err)).Add(1)
			for rows.Next() {
				ns = append(ns, notifier.Notification{})
				n := &ns[len(ns)-1]
				if err := rows.Scan(&n.ID, n); err != nil {
					return err
				}
			}

			if err := rows.Err(); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return nil, p, &clairerror.ErrBadNotification{
				NotificationID: id,
				E:              err,
			}
		}
		return ns, p, nil
	}

	// Page.Next being nil indicates a client's first request for a paged set of
	// notifications.
	if page.Next == nil {
		page.Next = &uuid.Nil
	}
	// If asking for a weird number of results, just error.
	if page.Size < 1 {
		return nil, notifier.Page{}, &clairerror.ErrBadNotification{
			NotificationID: id,
			E:              fmt.Errorf("bad page size: %d", page.Size),
		}
	}
	// Add one to limit to determine if there is another page to fetch.
	limit := page.Size + 1

	ns := make([]notifier.Notification, 0, limit)
	err := s.pool.AcquireFunc(ctx, func(c *pgxpool.Conn) error {
		var err error
		timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
			notificationsDuration.WithLabelValues(`pagedQuery`, errLabel(err)).Observe(v)
		}))
		defer timer.ObserveDuration()
		var rows pgx.Rows
		rows, err = c.Query(ctx, pagedQuery, id, page.Next, limit)
		notificationsCounter.WithLabelValues(`pagedQuery`, errLabel(err)).Add(1)
		for rows.Next() {
			ns = append(ns, notifier.Notification{})
			n := &ns[len(ns)-1]
			if err := rows.Scan(&n.ID, n); err != nil {
				return err
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, notifier.Page{}, &clairerror.ErrBadNotification{
			NotificationID: id,
			E:              err,
		}
	}

	// Page to return to client.
	outPage := notifier.Page{Size: page.Size}
	if len(ns) == limit {
		// Slice off the last element as it was only an indicator that another
		// page should be delivered.
		//
		// Set outPage.Next to the final element id being returned to the
		// caller.
		ns = ns[:page.Size]
		outPage.Next = &(ns[len(ns)-1].ID)
	}
	return ns, outPage, nil
}

// PutNotifications persists the provided notifications and associates them with
// the provided notification ID.
//
// PutNotifications must update the latest update operation for the provided
// updater in such a way that UpdateOperation returns the provided update
// operation ID when queried with the updater name.
//
// PutNotifications must create a Receipt with status created status on
// successful persistence of notifications in such a way that
// Receipter.Created() returns the persisted notification ID.
func (s *Store) PutNotifications(ctx context.Context, opts notifier.PutOpts) error {
	const (
		insertNotification    = `INSERT INTO notification (id) VALUES ($1);`
		insertUpdateOperation = `INSERT INTO notifier_update_operation (updater, uo_id, ts) VALUES ($1, $2, CURRENT_TIMESTAMP);`
		insertReceipt         = `INSERT INTO receipt (notification_id, uo_id, status, ts) VALUES ($1, $2, 'created', CURRENT_TIMESTAMP);`
	)
	txOpt := pgx.TxOptions{
		IsoLevel:   pgx.ReadCommitted,
		AccessMode: pgx.ReadWrite,
	}
	metrics := statusMetrics{
		dur:      putNotificationsDuration,
		counter:  putNotificationsCounter,
		affected: putNotificationsAffected,
	}

	err := s.pool.BeginTxFunc(ctx, txOpt, func(tx pgx.Tx) error {
		if err := txExec(ctx, metrics, tx,
			`insertNotification`, insertNotification,
			[]interface{}{opts.NotificationID}); err != nil {
			return err
		}
		if err := func() error {
			const name = `copyNotificationBody`
			// Batch insert via the Copy API. This needs its own little closure
			// here because it's using the lower-level API.
			src := copyNotifications(&opts.NotificationID, opts.Notifications)
			var err error
			timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
				putNotificationsDuration.WithLabelValues(name, errLabel(err)).Observe(v)
			}))
			defer timer.ObserveDuration()
			ct, err := tx.CopyFrom(ctx, pgx.Identifier{"notification_body"}, src.Columns(), src)
			putNotificationsCounter.WithLabelValues(name, errLabel(err)).Add(1)
			putNotificationsAffected.WithLabelValues(name, errLabel(err)).Add(float64(ct))
			if err != nil {
				return err
			}
			if got, want := ct, int64(len(opts.Notifications)); got != want {
				return fmt.Errorf("inserted %d/%d rows", got, want)
			}
			return nil
		}(); err != nil {
			return err
		}
		if err := txExec(ctx, metrics, tx,
			`insertUpdateOperation`, insertUpdateOperation,
			[]interface{}{opts.Updater, opts.UpdateID}); err != nil {
			return err
		}
		if err := txExec(ctx, metrics, tx,
			`insertReceipt`, insertReceipt,
			[]interface{}{opts.NotificationID, opts.UpdateID}); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return &clairerror.ErrPutNotifications{
			NotificationID: opts.NotificationID,
			E:              err,
		}
	}
	return nil
}

func copyNotifications(id *uuid.UUID, ns []notifier.Notification) *notificationSource {
	s := notificationSource{
		id: id,
		ns: ns,
	}
	s.enc = json.NewEncoder(&s.buf)
	return &s
}

type notificationSource struct {
	err error
	enc *json.Encoder
	id  *uuid.UUID
	buf bytes.Buffer
	ns  []notifier.Notification
}

func (r *notificationSource) Next() bool {
	return len(r.ns) > 0
}

func (r *notificationSource) Values() ([]interface{}, error) {
	n := &r.ns[0]
	r.ns = r.ns[1:]
	n.ID = uuid.New()
	r.buf.Reset()
	if err := r.enc.Encode(n); err != nil {
		r.err = err
		r.ns = nil
		return nil, err
	}
	return []interface{}{n.ID, r.id, r.buf.Bytes()}, nil
}

func (r *notificationSource) Err() error {
	if r.err != nil {
		return r.err
	}
	return nil
}

func (r *notificationSource) Columns() []string {
	return []string{"id", "notification_id", "body"}
}

// CollectNotifications garbage collects all notifications.
//
// Normally Receipter.SetDeleted will be issued first, however application logic
// may decide to gc notifications which have not been set deleted after some
// period of time, thus this condition should not be checked.
func (s *Store) CollectNotifications(ctx context.Context) error {
	ctx = zlog.ContextWithValues(ctx, "component", "notifier/postgres/Store.CollectNotifications")
	const (
		tryLock            = `SELECT pg_try_advisory_xact_lock($1, $2);`
		deleteNotification = `DELETE FROM notification USING receipt WHERE id = receipt.notification_id AND receipt.status = 'deleted'::receiptstatus;`
		deleteUpdateOp     = `DELETE FROM notifier_update_operation
	WHERE uo_id IN (
		SELECT uo_id FROM notifier_update_operation
		EXCEPT
		SELECT uo_id FROM receipt);`
		deleteReceipts = `DELETE FROM receipt
	WHERE
		ts < date_trunc('day', (now() - INTERVAL '14 days'))
		AND
		status <> 'created'::receiptstatus;`
	)
	txOpt := pgx.TxOptions{
		IsoLevel:   pgx.ReadCommitted,
		AccessMode: pgx.ReadWrite,
	}
	metrics := statusMetrics{
		dur:      gcNotificationDuration,
		counter:  gcNotificationCounter,
		affected: gcNotificationAffected,
	}

	err := s.pool.BeginTxFunc(ctx, txOpt, func(tx pgx.Tx) error {
		var ok bool
		if err := tx.QueryRow(ctx, tryLock, adminKeyspace, gcLock).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			// unable to lock
			return nil
		}
		if err := txExec(ctx, metrics, tx, "deleteNotification", deleteNotification, nil); err != nil {
			return err
		}
		if err := txExec(ctx, metrics, tx, "deleteReceipts", deleteReceipts, nil); err != nil {
			return err
		}
		if err := txExec(ctx, metrics, tx, "deleteUpdateOp", deleteUpdateOp, nil); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}
