package config

import "time"

// These are defaults, used in the documented spots.
const (
	// DefaultAddress is used if an "http_listen_addr" is not provided in the config.
	DefaultAddress = ":6060"
	// DefaultScanLockRetry is the default retry period for attempting locks
	// during the indexing process. Its name is a historical accident.
	DefaultScanLockRetry = 1
	// DefaultMatcherPeriod is the default interval for running updaters.
	DefaultMatcherPeriod = 6 * time.Hour
	// DefaultUpdateRetention is the number of updates per vulnerability
	// database to retain.
	DefaultUpdateRetention = 10
	// DefaultNotifierPollInterval is the default (and minimum) interval for the
	// notifier's change poll interval. The notifier will poll the database for
	// updated vulnerability databases at this rate.
	DefaultNotifierPollInterval = 5 * time.Second
	// DefaultNotifierDeliveryInterval is the default (and minimum) interval for
	// the notifier's delivery interval. The notifier will attempt to deliver
	// outstanding notifications at this rate.
	DefaultNotifierDeliveryInterval = 5 * time.Second
)

// BUG(hank) The DefaultNotifierPollInterval is absurdly low.

// BUG(hank) The DefaultNotifierDeliveryInterval is absurdly low.
