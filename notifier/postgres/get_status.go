package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	createdCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "created_total",
			Help:      "Total number of database queries issued in the created method",
		},
		[]string{"query", "error"},
	)
	createdDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "created_duration_seconds",
			Help:      "Duration of all queries issued in the created method",
		},
		[]string{"query", "error"},
	)
	failedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "failed_total",
			Help:      "Total number of database queries issued in the failed method",
		},
		[]string{"query", "error"},
	)
	failedDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "failed_duration_seconds",
			Help:      "Duration of all queries issued in the failed method",
		},
		[]string{"query", "error"},
	)
	deletedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "deleted_total",
			Help:      "Total number of database queries issued in the deleted method",
		},
		[]string{"query", "error"},
	)
	deletedDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "deleted_duration_seconds",
			Help:      "Duration of all queries issued in the deleted method",
		},
		[]string{"query", "error"},
	)
)

func (s *Store) getStatus(ctx context.Context, status string, m statusMetrics) ([]uuid.UUID, error) {
	const (
		query = `SELECT notification_id FROM receipt WHERE status = $1::receiptstatus;`
	)

	ids := []uuid.UUID{}
	err := s.pool.AcquireFunc(ctx, func(c *pgxpool.Conn) error {
		var err error
		var rows pgx.Rows
		timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
			m.dur.WithLabelValues(`query`, errLabel(err)).Observe(v)
		}))
		defer timer.ObserveDuration()
		rows, err = c.Query(ctx, query, status)
		m.counter.WithLabelValues(`query`, errLabel(err)).Add(1)
		if err != nil {
			return err
		}
		var id uuid.UUID
		for rows.Next() {
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ids, nil
}

// Created will return all notification ids in "created" status.
func (s *Store) Created(ctx context.Context) ([]uuid.UUID, error) {
	ids, err := s.getStatus(ctx, `created`, statusMetrics{
		counter: createdCounter,
		dur:     createdDuration,
	})
	if err != nil {
		return nil, err
	}
	return ids, nil
}

// Failed will return all notification ids in "delivery_failed" status.
func (s *Store) Failed(ctx context.Context) ([]uuid.UUID, error) {
	ids, err := s.getStatus(ctx, `delivery_failed`, statusMetrics{
		counter: failedCounter,
		dur:     failedDuration,
	})
	if err != nil {
		return nil, err
	}
	return ids, nil
}

// Deleted will return all notification ids in "deleted" status.
func (s *Store) Deleted(ctx context.Context) ([]uuid.UUID, error) {
	ids, err := s.getStatus(ctx, `deleted`, statusMetrics{
		counter: deletedCounter,
		dur:     deletedDuration,
	})
	if err != nil {
		return nil, err
	}
	return ids, nil
}
