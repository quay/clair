package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	clairerror "github.com/quay/clair/v4/clair-error"
)

var (
	setDeletedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "setdeleted_total",
			Help:      "Total number of database queries issued in the setDeleted method",
		},
		[]string{"query", "error"},
	)
	setDeletedDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "setdeleted_duration_seconds",
			Help:      "Duration of all queries issued in the setDeleted method",
		},
		[]string{"query", "error"},
	)
	setDeliveredCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "setdelivered_total",
			Help:      "Total number of database queries issued in the setDelivered method",
		},
		[]string{"query", "error"},
	)
	setDeliveredDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "setdelivered_duration_seconds",
			Help:      "Duration of all queries issued in the setDelivered method",
		},
		[]string{"query", "error"},
	)
	setDeliveryFailedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "setdeliveryfailed_total",
			Help:      "Total number of database queries issued in the setDeliveryFailed method",
		},
		[]string{"query", "error"},
	)
	setDeliveryFailedDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "setdeliveryfailed_duration_seconds",
			Help:      "Duration of all queries issued in the setDeliveryFailed method",
		},
		[]string{"query", "error"},
	)
)

func (s *Store) setStatus(ctx context.Context, id uuid.UUID, status string, m statusMetrics) error {
	const query = `UPDATE receipt SET status = $1::receiptstatus, ts = CURRENT_TIMESTAMP WHERE notification_id = $2::uuid;`
	return s.pool.AcquireFunc(ctx, func(c *pgxpool.Conn) error {
		var err error
		var tag pgconn.CommandTag
		timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
			m.dur.WithLabelValues(`query`, errLabel(err)).Observe(v)
		}))
		defer timer.ObserveDuration()
		tag, err = c.Exec(ctx, query, status, id)
		m.counter.WithLabelValues(`query`, errLabel(err)).Add(1)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return &clairerror.ErrNoReceipt{NotificationID: id}
		}
		return nil
	})
}

// SetDelivered marks the provided notification id as delivered
func (s *Store) SetDelivered(ctx context.Context, id uuid.UUID) error {
	return s.setStatus(ctx, id, `delivered`, statusMetrics{
		counter: setDeliveredCounter,
		dur:     setDeliveredDuration,
	})
}

// SetDeliveryFailed marks the provided notification id failed to be delivere
func (s *Store) SetDeliveryFailed(ctx context.Context, id uuid.UUID) error {
	return s.setStatus(ctx, id, `delivery_failed`, statusMetrics{
		counter: setDeliveryFailedCounter,
		dur:     setDeliveryFailedDuration,
	})
}

// SetDeleted marks the provided notification id as deleted
func (s *Store) SetDeleted(ctx context.Context, id uuid.UUID) error {
	return s.setStatus(ctx, id, `deleted`, statusMetrics{
		counter: setDeletedCounter,
		dur:     setDeletedDuration,
	})
}
