# Config

## CLI Flags And Environment Variables

Clair is configured by a structured yaml file. 
Each Clair node needs to specify what mode it will run in and a path to a
configuration file via CLI flags or environment variables.

For example:
```shell
$ clair -conf ./path/to/config.yaml -mode indexer
$ clair -conf ./path/to/config.yaml -mode matcher
```

```
-mode 
    (also specified by CLAIR_MODE env variable)
    One of the following strings
    Sets which mode the clair instances will run in
    
    "indexer": runs just the indexer node
    "matcher": runs just the matcher node
    "notifier": runs just the notifier node
    "combo": will run all services on the same node.
-conf
    (also specified by CLAIR_CONF env variable)
    A file system path to Clair's config file
```

The above example starts two Clair nodes using the same configuration.
One will only run the indexing facilities while the other will only run the
matching facilities.

Environment variables respected by the Go standard library can be specified
if needed. Some notable examples:

* `HTTP_PROXY`
* `HTTPS_PROXY`
* `SSL_CERT_DIR`

If running in "combo" mode you **must** supply the `indexer`, `matcher`,
and `notifier` configuration blocks in the configuration.

## Configuration Reference

```
http_listen_addr: ""
introspection_addr: ""
log_level: ""
indexer:
    connstring: ""
    scanlock_retry: 0
    layer_scan_concurrency: 0
    migrations: false
    scanner: {}
    airgap: false
matcher:
    connstring: ""
    max_conn_pool: 0
    indexer_addr: ""
    migrations: false
    period: ""
    disable_updaters: false
    update_retention: 2
matchers:
    names: nil
    config: nil
updaters:
    sets: nil
    config: nil
notifier:
    connstring: ""
    migrations: false
    indexer_addr: ""
    matcher_addr: ""
    poll_interval: ""
    delivery_interval: ""
    disable_summary: false
    webhook: null
    amqp: null
    stomp: null
auth: 
  psk: nil
trace:
    name: ""
    probability: null
    jaeger:
        agent:
            endpoint: ""
        collector:
            endpoint: ""
            username: null
            password: null
        service_name: ""
        tags: nil
        buffer_max: 0
metrics:
    name: ""
    prometheus:
        endpoint: null
    dogstatsd:
        url: ""
```

Note: the above just lists every key for completeness. Copy-pasting the above as
a starting point for configuration will result in some options not having their
defaults set normally.

### `$.http_listen_addr`
A string in `<host>:<port>` format where `<host>` can be an empty string.

This configures where the HTTP API is exposed.
See `/openapi/v1` for the API spec.

### `$.introspection_addr`
A string in `<host>:<port>` format where `<host>` can be an empty string.

This configures where Clair's metrics and health endpoints are exposed.

### `$.log_level`
Set the logging level.

One of the following strings:
* debug-color
* debug
* info
* warn
* error
* fatal
* panic

### `$.indexer`
Indexer provides Clair Indexer node configuration.

#### `$.indexer.connstring`
A Postgres connection string.

Accepts a format as a url (e.g.,
`postgres://pqgotest:password@localhost/pqgotest?sslmode=verify-full`)
or a libpq connection string (e.g.,
`user=pqgotest dbname=pqgotest sslmode=verify-full`).

#### `$.indexer.scanlock_retry`
A positive integer representing seconds.

Concurrent Indexers lock on manifest scans to avoid clobbering.
This value tunes how often a waiting Indexer will poll for the lock.
<!--TODO: Move to async operating mode -->

#### `$.indexer.layer_scan_concurrency`
Positive integer limiting the number of concurrent layer scans.

Indexers will index a Manifest's layers concurrently.
This value tunes the number of layers an Indexer will scan in parallel.

#### `$.indexer.migrations`
A boolean value.

Whether Indexer nodes handle migrations to their database.

#### `$.indexer.scanner`
A map with the name of a particular scanner and arbitrary yaml as a value.

Scanner allows for passing configuration options to layer scanners.
The scanner will have this configuration passed to it on construction if
designed to do so.

### `$.matcher`
Matcher provides Clair matcher node configuration.

#### `$.matcher.connstring`
A Postgres connection string.

Accepts a format as a url (e.g.,
`postgres://pqgotest:password@localhost/pqgotest?sslmode=verify-full`)
or a libpq connection string (e.g.,
`user=pqgotest dbname=pqgotest sslmode=verify-full`).


#### `$.matcher.max_conn_pool`
A positive integer limiting the database connection pool size.

Clair allows for a custom connection pool size.
This number will directly set how many active database
connections are allowed concurrently.

#### `$.matcher.indexer_addr`
A string in `<host>:<port>` format where `<host>` can be an empty string.

A Matcher contacts an Indexer to create a VulnerabilityReport.
The location of this Indexer is required.

#### `$.matcher.migrations`
A boolean value.

Whether Matcher nodes handle migrations to their databases.

#### `$.matcher.period`
A time.ParseDuration parseable string.

Determines how often updates for new security advisories will take place.

Defaults to 30 minutes.

#### `$.matcher.disable_updaters`
A boolean value.

Whether to run background updates or not.

#### `$.matcher.update_retention`
An integer value limiting the number of update operations kept in the database.

Sets the number of update operations to retain between garbage collection
cycles. This should be set to a safe MAX value based on database size
constraints.

Defaults to 10.

If a value less than 0 is provided, GC is disabled. 2 is the minimum value to
ensure updates can be compared for notifications. 

### `$.matchers`
Matchers provides configuration for the in-tree Matchers and RemoteMatchers.

#### `$.matchers.names`
A list of string values informing the matcher factory about enabled matchers.

If the value is nil the default list of Matchers will run:
* alpine
* aws
* debian
* oracle
* photon
* python
* rhel
* suse
* ubuntu
* crda

If an empty list is provided zero matchers will run.

#### `$.matchers.config`
Provides configuration to specific matcher.

A map keyed by the name of the matcher containing a sub-object which
will be provided to the matchers factory constructor.

A hypothetical example:

    config:
      python:
        ignore_vulns:
          - CVE-XYZ
          - CVE-ABC

### `$.updaters`
Updaters provides configuration for the Matcher's update manager.

#### `$.updaters.sets`
A list of string values informing the update manager which Updaters to run.

If the value is nil (or `null` in yaml) the default set of Updaters will run:
* alpine
* aws
* debian
* oracle
* photon
* pyupio
* rhel
* suse
* ubuntu

If an empty list is provided zero updaters will run.

#### `$.updaters.config`
Provides configuration to specific updater sets.

A map keyed by the name of the updater set name containing a sub-object
which will be provided to the updater set's constructor.

A hypothetical example:

    config:
      ubuntu:
        security_tracker_url: http://security.url
        ignore_distributions: 
          - cosmic

### `$.notifier`
Notifier provides Clair notifier node configuration.

#### `$.notifier.connstring`
A Postgres connection string.

Accepts a format as a url (e.g.,
`postgres://pqgotest:password@localhost/pqgotest?sslmode=verify-full`)
or a libpq connection string (e.g.,
`user=pqgotest dbname=pqgotest sslmode=verify-full`).

#### `$.notifier.migrations`
A boolean value.

Whether Notifier nodes handle migrations to their database.

#### `$.notifier.indexer_addr`
A string in `<host>:<port>` format where `<host>` can be an empty string.

A Notifier contacts an Indexer to create obtain manifests affected by
vulnerabilities. The location of this Indexer is required.

#### `$.notifier.matcher_addr`
A string in `<host>:<port>` format where `<host>` can be an empty string.

A Notifier contacts a Matcher to list update operations and acquire diffs.
The location of this Indexer is required.

#### `$.notifier.poll_interval`
A time.ParseDuration parsable string.

The frequency at which the notifier will query at Matcher for Update Operations.

#### `$.notifier.delivery_interval`
A time.ParseDuration parsable string.

The frequency at which the notifier attempt delivery of created or previously
failed notifications.

#### `$.notifier.disable_summary`
A boolean.

Controls whether notifications should be summarized to one per manifest or not.

#### `$.notifier.webhook`
Configures the notifier for webhook delivery.

#### `$.notifier.webhook.target`
URL where the webhook will be delivered.

#### `$.notifier.webhook.callback`
The callback url where notifications can be retrieved.
The notification ID will be appended to this url.

This will typically be where the clair notifier is hosted.

#### `$.notifier.webhook.headers`
A map associating a header name to a list of values.

#### `$.notifier.amqp`
Configures the notifier for AMQP delivery.

Note: Clair does not declare any AMQP components on its own.  All attempts
to use an exchange or queue are passive only and will fail The broker
administrators should setup exchanges and queues ahead of time.

#### `$.notifier.amqp.direct`
A boolean value.

If true the Notifier will deliver individual notifications (not a callback)
to the configured AMQP broker.

#### `$.notifier.amqp.rollup`
Integer 0 or greater.

If `direct` is true this value will inform notifier how many notifications
to send in a single direct delivery.  For example, if `direct` is set to
`true` and `rollup` is set to `5`, the notifier will deliver no more then
5 notifications in a single json payload to the broker. Setting the value
to 0 will effectively set it to 1.

#### `$.notifier.amqp.exchange`
The AMQP Exchange to connect to.

#### `$.notifier.amqp.exchange.name`
string value

The name of the exchange to connect to.

#### `$.notifier.amqp.exchange.type`
string value

The type of the exchange. Typically:
* direct
* fanout
* topic
* headers

#### `$.notifier.amqp.exchange.durability`
bool value

Whether the configured queue is durable or not.

#### `$.notifier.amqp.exchange.auto_delete`
bool value

Whether the configured queue uses an auto_delete policy.

#### `$.notifier.amqp.exchange.routing_key`
string value

The name of the routing key each notification will be sent with.

#### `$.notifier.amqp.callback`
a URL string

If `direct` is `false`, this URL is provided in the notification callback sent
to the broker. This URL should point to Clair's notification API endpoint.

#### `$.notifier.amqp.uris`
list of URL strings

A list of one or more AMQP brokers to connect to, in priority order.

#### `$.notifier.amqp.tls`
Configures TLS connection to AMQP broker.

#### `$.notifier.amqp.tls.root_ca`
string value

The filesystem path where a root CA can be read.

#### `$.notifier.amqp.tls.cert`
string value

The filesystem path where a tls certificate can be read. Note that clair
also respects `SSL_CERT_DIR`, as documented for the Go `crypto/x509` package.

#### `$.notifier.amqp.tls.key`
string value

The filesystem path where a TLS private key can be read.

#### `$.notifier.stomp`
Configures the notifier for STOMP delivery.

#### `$.notifier.stomp.direct`
A boolean value.

If `true`, the Notifier will deliver individual notifications (not a
callback) to the configured STOMP broker.

#### `$.notifier.stomp.rollup`
Integer 0 or greater.

If `direct` is `true`, this value will limit the number of notifications
sent in a single direct delivery.  For example, if `direct` is set to
`true` and `rollup` is set to `5`, the notifier will deliver no more
then 5 notifications in a single json payload to the broker. Setting the value
to 0 will effectively set it to 1.

#### `$.notifier.stomp.callback`
a URL string

If `direct` is `false`, this URL is provided in the notification callback sent
to the broker. This URL should point to Clair's notification API endpoint.

#### `$.notifier.stomp.destination`
a string value

The STOMP destination to deliver notifications to. 

#### `$.notifier.stomp.uris`
list of URL strings

A list of one or more STOMP brokers to connect to in priority order.

#### `$.notifier.stomp.tls`
Configures TLS connection to STOMP broker.

#### `$.notifier.stomp.tls.root_ca`
string value

The filesystem path where a root CA can be read.
Note that clair also respects `SSL_CERT_DIR`, as documented for the Go
`crypto/x509` package.

#### `$.notifier.stomp.tls.cert`
string value

The filesystem path where a tls certificate can be read.

#### `$.notifier.stomp.tls.key`
string value

The filesystem path where a tls private key can be read.

#### `$.notifier.stomp.tls.user`
Configures login information for connecting to a STOMP broker.

#### `$.notifier.stomp.tls.login`
string value

The STOMP login to connect with.

#### `$.notifier.stomp.tls.passcode`
string value

The STOMP passcode to connect with.

### `$.auth`
Defines ClairV4's external and intra-service JWT based authentication.

If multiple auth mechanisms are defined, the Keyserver is preferred.

### `$.auth.psk`
Defines preshared key authentication.

#### `$.auth.psk.key`
a string value

A shared base64 encoded key distributed between all parties signing and
verifying JWTs.

#### `$.auth.psk.iss`
a list of string value

A list of JWT issuers to verify. An empty list will accept any issuer in a
JWT claim.

### `$.auth.keyserver`
Defines Quay keyserver authentication.

#### `$.auth.keyserver.api`
a string value

The API where Quay Keyserver can be reached.

#### `$.auth.keyserver.intraservice`
a string value

A key shared between all Clair nodes for intra-service JWT authentication.

### `$.trace`
Defines distributed tracing configuration based on OpenTelemetry.

#### `$.trace.name`
a string value

The name of the application traces will belong to.

#### `$.trace.probability`
a float value

The probability a trace will occur.

#### `$.trace.jaeger`
Defines values for Jaeger tracing.

#### `$.trace.jaeger.agent`
Defines values for configuring delivery to a Jaeger agent.

#### `$.trace.jaeger.agent.endpoint`
a string value

An address in `<host>:<post>` syntax where traces can be submitted.

#### `$.trace.jaeger.collector`
Defines values for configuring delivery to a Jaeger collector.

#### `$.trace.jaeger.collector.endpoint`
a string value

An address in `<host>:<post>` syntax where traces can be submitted.

#### `$.trace.jaeger.collector.username`
a string value

#### `$.trace.jaeger.collector.password`
a string value

#### `$.trace.jaeger.service_name`
a string value

#### `$.trace.jaeger.tags`
a mapping of a string to a string

#### `$.trace.jaeger.buffer_max`
an integer value

### `$.metrics`
Defines distributed tracing configuration based on OpenTelemetry.

#### `$.metrics.name`
a string value

### `$.metrics.prometheus`
Configuration for a prometheus metrics exporter.

#### `$.metrics.prometheus.endpoint`
a string value

Defines the path where metrics will be served.
