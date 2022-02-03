package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/notifier"
)

var (
	notificationsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "notifications_total",
			Help:      "Total number of database queries issued in the notifications method.",
		},
		[]string{"query"},
	)
	notificationsDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "notifications_duration_seconds",
			Help:      "The duration of all queries issued in the notifications method",
		},
		[]string{"query"},
	)
)

func notifications(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID, page *notifier.Page) ([]notifier.Notification, notifier.Page, error) {
	const (
		query      = "SELECT id, body FROM notification_body WHERE notification_id = $1"
		pagedQuery = "SELECT id, body FROM notification_body WHERE notification_id = $1 AND id > $2 ORDER BY id ASC LIMIT $3"
	)

	// if no page argument early return all notifications
	if page == nil {
		p := notifier.Page{}
		notifications := make([]notifier.Notification, 0, 0)
		start := time.Now()
		rows, err := pool.Query(ctx, query, id.String())
		if err != nil {
			return nil, notifier.Page{}, clairerror.ErrBadNotification{id, err}
		}
		notificationsCounter.WithLabelValues("query").Add(1)
		notificationsDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())
		defer rows.Close()
		for rows.Next() {
			var n notifier.Notification
			err := rows.Scan(&n.ID, &n)
			if err != nil {
				return nil, p, clairerror.ErrBadNotification{id, err}
			}
			notifications = append(notifications, n)
		}
		if err := rows.Err(); err != nil {
			return nil, notifier.Page{}, clairerror.ErrBadNotification{id, err}
		}
		return notifications, p, nil
	}

	// page to return to client
	outPage := notifier.Page{
		Size: page.Size,
	}

	// page.Next being nil indicates a client's first
	// request for a paged set of notifications.
	if page.Next == nil {
		page.Next = &uuid.Nil
	}

	// add one to limit to determine if there is
	// another page to fetch
	limit := page.Size + 1

	start := time.Now()
	notifications := make([]notifier.Notification, 0, limit)
	rows, err := pool.Query(ctx, pagedQuery, id, page.Next, limit)
	if err != nil {
		return nil, notifier.Page{}, clairerror.ErrBadNotification{id, err}
	}
	notificationsCounter.WithLabelValues("pagedQuery").Add(1)
	notificationsDuration.WithLabelValues("pagedQuery").Observe(time.Since(start).Seconds())

	defer rows.Close()
	for rows.Next() {
		var n notifier.Notification
		err := rows.Scan(&n.ID, &n)
		if err != nil {
			return nil, notifier.Page{}, clairerror.ErrBadNotification{id, err}
		}
		notifications = append(notifications, n)
	}
	if err := rows.Err(); err != nil {
		return nil, notifier.Page{}, clairerror.ErrBadNotification{id, err}
	}

	morePages := len(notifications) == limit
	if morePages {
		// Slice off the last element as it was only an indicator
		// that another page should be delivered.
		//
		// Set outPage.Next to the final element id being returned
		// to the caller.
		notifications = notifications[:page.Size]
		outPage.Next = &(notifications[page.Size-1].ID)
	} else {
		outPage.Next = nil
	}

	return notifications, outPage, nil
}
