package database

import (
	"errors"
	"time"
)

var (
	// ErrTransaction is an error that occurs when a database transaction fails.
	// ErrTransaction = errors.New("database: transaction failed (concurrent modification?)")

	// ErrBackendException is an error that occurs when the database backend does
	// not work properly (ie. unreachable).
	ErrBackendException = errors.New("database: an error occured when querying the backend")

	// ErrInconsistent is an error that occurs when a database consistency check
	// fails (ie. when an entity which is supposed to be unique is detected twice)
	ErrInconsistent = errors.New("database: inconsistent database")

	// ErrCantOpen is an error that occurs when the database could not be opened
	ErrCantOpen = errors.New("database: could not open database")
)

type Datastore interface {
	// Layer
	InsertLayer(Layer) error
	FindLayer(name string, withFeatures, withVulnerabilities bool) (layer Layer, err error)
	DeleteLayer(name string) error

	// Vulnerability
	InsertVulnerabilities([]Vulnerability) error
	// DeleteVulnerability(id string) error
	FindVulnerability(namespaceName, name string) (Vulnerability, error)

	// Notifications
	// InsertNotifications([]Notification) error
	// FindNotificationToSend() (Notification, error)
	// CountNotificationsToSend() (int, error)
	// MarkNotificationAsSent(id string)

	// Key/Value
	InsertKeyValue(key, value string) error
	GetKeyValue(key string) (string, error)

	// Lock
	Lock(name string, owner string, duration time.Duration, renew bool) (bool, time.Time)
	Unlock(name, owner string)
	FindLock(name string) (string, time.Time, error)

	Close()
}
