package config

import (
	"github.com/quay/clair/v4/notifier/amqp"
	"github.com/quay/clair/v4/notifier/stomp"
	"github.com/quay/clair/v4/notifier/webhook"
)

// Notifier provides Clair Notifier node configuration
type Notifier struct {
	// A Postgres connection string.
	//
	// Formats:
	// url: "postgres://pqgotest:password@localhost/pqgotest?sslmode=verify-full"
	// or
	// string: "user=pqgotest dbname=pqgotest sslmode=verify-full"
	ConnString string `yaml:"connstring" json:"connstring"`
	// A "true" or "false" value
	//
	// Whether Notifier nodes handle migrations to their database.
	Migrations bool `yaml:"migrations" json:"migrations"`
	// A string in <host>:<port> format where <host> can be an empty string.
	//
	// A Notifier contacts an Indexer to create obtain manifests affected by vulnerabilities.
	// The location of this Indexer is required.
	IndexerAddr string `yaml:"indexer_addr" json:"indexer_addr"`
	// A string in <host>:<port> format where <host> can be an empty string.
	//
	// A Notifier contacts a Matcher to list update operations and acquire diffs.
	// The location of this Indexer is required.
	MatcherAddr string `yaml:"matcher_addr" json:"matcher_addr"`
	// A time.ParseDuration parsable string
	//
	// The frequency at which the notifier will query at Matcher for Update Operations.
	PollInterval string `yaml:"poll_interval" json:"poll_interval"`
	// A time.ParseDuration parsable string
	//
	// The frequency at which the notifier attempt delivery of created or previously failed
	// notifications
	DeliveryInterval string `yaml:"delivery_interval" json:"delivery_interval"`
	// DisableSummary disables summarizing vulnerabilities per-manifest.
	//
	// The default is to summarize any new vulnerabilities to the most severe
	// one, in the thought that any additional processing for end-user
	// notifications can have policies around severity and fetch a complete
	// VulnerabilityReport if it'd like.
	//
	// For a machine-consumption use case, it may be easier to instead have the
	// notifier push all the data.
	DisableSummary bool `yaml:"disable_summary" json:"disable_summary"`
	// Only one of the following should be provided in the configuration
	//
	// Configures the notifier for webhook delivery
	Webhook *webhook.Config `yaml:"webhook" json:"webhook"`
	// Configures the notifier for AMQP delivery.
	AMQP *amqp.Config `yaml:"amqp" json:"amqp"`
	// Configures the notifier for STOMP delivery.
	STOMP *stomp.Config `yaml:"stomp" json:"stomp"`
}
