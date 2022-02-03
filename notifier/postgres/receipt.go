package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/notifier"
)

var (
	receiptCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "receipt_total",
			Help:      "Total number of database queries issued in the receipt method",
		},
		[]string{"query", "error"},
	)
	receiptDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "receipt_duration_seconds",
			Help:      "Duration of all queries issued in the receipt method",
		},
		[]string{"query", "error"},
	)
	receiptByUOIDCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "receiptbyuoid_total",
			Help:      "Total number of database queries issued in the receiptByUOID method",
		},
		[]string{"query", "error"},
	)
	receiptByUOIDDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "receiptbyuoid_duration_seconds",
			Help:      "Duration of all queries issued in the receiptByUOID method",
		},
		[]string{"query", "error"},
	)
	putReceiptCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "putreceipt_total",
			Help:      "Total number of database queries issued in the putReceipt method",
		},
		[]string{"query", "error"},
	)
	putReceiptAffected = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "putreceipt_affected_total",
			Help:      "Total number of rows affected in the putReceipt method",
		},
		[]string{"query", "error"},
	)
	putReceiptDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "putreceipt_duration_seconds",
			Help:      "Duration of all queries issued in the putReceipt method",
		},
		[]string{"query", "error"},
	)
)

// Receipt returns the Receipt for a given notification ID.
func (s *Store) Receipt(ctx context.Context, id uuid.UUID) (notifier.Receipt, error) {
	const query = `SELECT uo_id, notification_id, status, ts FROM receipt WHERE notification_id = $1::uuid;`
	var r notifier.Receipt
	f := getReceipt(ctx, &r, query, `query`, id, statusMetrics{
		counter: receiptCounter,
		dur:     receiptDuration,
	})
	return r, s.pool.AcquireFunc(ctx, f)
}

// ReceiptByUOID returns the Receipt for a given UpdateOperation ID.
func (s *Store) ReceiptByUOID(ctx context.Context, id uuid.UUID) (notifier.Receipt, error) {
	const query = `SELECT uo_id, notification_id, status, ts FROM receipt WHERE uo_id = $1::uuid;`
	var r notifier.Receipt
	f := getReceipt(ctx, &r, query, `query`, id, statusMetrics{
		counter: receiptByUOIDCounter,
		dur:     receiptByUOIDDuration,
	})
	return r, s.pool.AcquireFunc(ctx, f)
}

func getReceipt(ctx context.Context, r *notifier.Receipt, query, name string, id uuid.UUID, m statusMetrics) func(*pgxpool.Conn) error {
	return func(c *pgxpool.Conn) error {
		var err error
		timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
			m.dur.WithLabelValues(`query`, errLabel(err)).Observe(v)
		}))
		defer timer.ObserveDuration()
		err = c.QueryRow(ctx, query, id).Scan(
			&r.UOID,
			&r.NotificationID,
			&r.Status,
			&r.TS,
		)
		receiptCounter.WithLabelValues("query", errLabel(err)).Add(1)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return &clairerror.ErrNoReceipt{
				NotificationID: id,
			}
		case err != nil:
			return &clairerror.ErrReceipt{
				NotificationID: id,
				E:              err,
			}
		}
		return nil
	}
}

func (s *Store) PutReceipt(ctx context.Context, updater string, r notifier.Receipt) error {
	const (
		insertNotification    = `INSERT INTO notification (id) VALUES ($1);`
		insertReceipt         = `INSERT INTO receipt (notification_id, uo_id, status, ts) VALUES ($1, $2, $3, CURRENT_TIMESTAMP);`
		insertUpdateOperation = `INSERT INTO notifier_update_operation (updater, uo_id, ts) VALUES ($1, $2, CURRENT_TIMESTAMP);`
	)
	txOpt := pgx.TxOptions{
		IsoLevel:   pgx.ReadCommitted,
		AccessMode: pgx.ReadWrite,
	}
	metrics := statusMetrics{
		dur:      putReceiptDuration,
		counter:  putReceiptCounter,
		affected: putReceiptAffected,
	}
	err := s.pool.BeginTxFunc(ctx, txOpt, func(tx pgx.Tx) error {
		if err := txExec(ctx, metrics, tx,
			`insertNotification`,
			insertNotification,
			[]interface{}{r.NotificationID}); err != nil {
			return err
		}
		if err := txExec(ctx, metrics, tx,
			`insertUpdateOperation`,
			insertUpdateOperation,
			[]interface{}{updater, r.UOID}); err != nil {
			return err
		}
		if err := txExec(ctx, metrics, tx,
			`insertReceipt`,
			insertReceipt,
			[]interface{}{r.NotificationID, r.UOID, r.Status}); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}
