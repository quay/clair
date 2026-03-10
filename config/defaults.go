package config

import "time"

// These are defaults, used in the documented spots.
const (
	// DefaultAPIv1Network is used if a network for the v1 API is not provided
	// in the config.
	DefaultAPIv1Network = "tcp"
	// DefaultAPIv1Address is used if an address for the v1 API is not provided
	// in the config.
	DefaultAPIv1Address = ":6060"

	// DefaultIntrospectionNetwork is used if a network for the Introspection
	// server is not provided in the config.
	DefaultIntrospectionNetwork = "tcp"
	// DefaultIntrospectionAddress is used if an address for the Introspection
	// server is not provided in the config.
	DefaultIntrospectionAddress = ":8089"

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
	DefaultNotifierPollInterval = 6 * time.Hour
	// DefaultNotifierDeliveryInterval is the default (and minimum) interval for
	// the notifier's delivery interval. The notifier will attempt to deliver
	// outstanding notifications at this rate.
	DefaultNotifierDeliveryInterval = 1 * time.Hour
)

// DefaultAddress is the previous name of [DefaultAPIv1Address].
//
// Deprecated: Refer to [DefaultAPIv1Address] directly.
const DefaultAddress = DefaultAPIv1Address
