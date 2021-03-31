package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/clair/v4/notifier"
)

var (
	putReceiptCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "putreceipt_total",
			Help:      "Total number of database queries issued in the putReceipt method.",
		},
		[]string{"query"},
	)
	putReceiptDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "putreceipt_duration_seconds",
			Help:      "The duration of all queries issued in the putReceipt method",
		},
		[]string{"query"},
	)
)

func putReceipt(ctx context.Context, pool *pgxpool.Pool, updater string, r notifier.Receipt) error {
	const (
		insertNotification    = `INSERT INTO notification (id) VALUES ($1);`
		insertReceipt         = `INSERT INTO receipt (notification_id, uo_id, status, ts) VALUES ($1, $2, $3, CURRENT_TIMESTAMP);`
		insertUpdateOperation = `
		INSERT INTO notifier_update_operation (updater, uo_id, ts)
		VALUES ($1, $2, CURRENT_TIMESTAMP)
		`
	)
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to create tx: %v", err)
	}
	defer tx.Rollback(ctx)

	start := time.Now()
	tag, err := tx.Exec(ctx, insertNotification, r.NotificationID)
	if err != nil {
		return fmt.Errorf("failed to insert notification id: %v", err)
	}
	putReceiptCounter.WithLabelValues("insertNotification").Add(1)
	putReceiptDuration.WithLabelValues("insertNotification").Observe(time.Since(start).Seconds())
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("insert of notification id had no effect")
	}

	start = time.Now()
	tag, err = tx.Exec(ctx, insertUpdateOperation, updater, r.UOID)
	if err != nil {
		return fmt.Errorf("failed to insert update operation id: %v", err)
	}
	putReceiptCounter.WithLabelValues("insertUpdateOperation").Add(1)
	putReceiptDuration.WithLabelValues("insertUpdateOperation").Observe(time.Since(start).Seconds())
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("insert of update operation had no effect")
	}

	start = time.Now()
	tag, err = tx.Exec(ctx,
		insertReceipt,
		r.NotificationID,
		r.UOID,
		r.Status,
	)
	if err != nil {
		return fmt.Errorf("failed to insert receipt: %v", err)
	}
	putReceiptCounter.WithLabelValues("insertReceipt").Add(1)
	putReceiptDuration.WithLabelValues("insertReceipt").Observe(time.Since(start).Seconds())
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("insert of receipt had no effect")
	}
	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("failed to commit tx: %v", err)
	}
	return nil
}
