# Config

## CLI Flags And ENV Vars

ClairV4 is provided a structured yaml configuration. 
Each ClairV4 node will specify what mode it will run in and config path via cli flag or environment variable.

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
One will only run the indexing facilities while the other will only run the matching facilities.

If running in "combo" mode you **must** supply the `indexer`, `matcher`, and `notifier` configuration blocks in the configuration.

## Config Reference

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

### http_listen_addr: ""
```
A string in <host>:<port> format where <host> can be an empty string.

exposes Clair node's functionality to the network.
see /openapi/v1 for api spec.
```

### introspection_addr: ""
```
A string in <host>:<port> format where <host> can be an empty string.

exposes Clair's metrics and health endpoints.
```

### log_level: ""
```
Set the logging level.

One of the following strings:
"debug-color"
"debug"
"info"
"warn"
"error"
"fatal"
"panic"
```

### indexer: \<object\>
```
Indexer provides Clair Indexer node configuration
```

#### &emsp;connstring: ""
```
A Postgres connection string.

formats:
url: "postgres://pqgotest:password@localhost/pqgotest?sslmode=verify-full"
or
string: "user=pqgotest dbname=pqgotest sslmode=verify-full"
```

#### &emsp;scanlock_retry: 0
```
A positive value representing seconds.

Concurrent Indexers lock on manifest scans to avoid clobbering.
This value tunes how often a waiting Indexer will poll for the lock.
TODO: Move to async operating mode
```

#### &emsp;layer_scan_concurrency: 0
```
A positive values represeting quantity.

Indexers will index a Manifest's layers concurrently.
This value tunes the number of layers an Indexer will scan in parallel.
```

#### &emsp;migrations: false
```
A "true" or "false" value

Whether Indexer nodes handle migrations to their database.
```

#### &emsp;scanner: {}
```  
A map with the name of a particular scanner and arbitrary yaml as a value

Scanner allows for passing configuration options to layer scanners.
The scanner will have this configuration passed to it on construction if designed to do so.
```

### matcher: \<object\>
```
Matcher provides Clair matcher node configuration
```

#### &emsp;connstring: ""
```
A Postgres connection string.

Formats:
url: "postgres://pqgotest:password@localhost/pqgotest?sslmode=verify-full"
or
string: "user=pqgotest dbname=pqgotest sslmode=verify-full"
```


#### &emsp;max_conn_pool: 0
```
A positive integer

Clair allows for a custom connection pool size.
This number will directly set how many active sql
connections are allowed concurrently.
```

#### &emsp;indexer_addr: ""
```
A string in <host>:<port> format where <host> can be an empty string.

A Matcher contacts an Indexer to create a VulnerabilityReport.
The location of this Indexer is required.
```

#### &emsp;migrations: false
```
A "true" or "false" value

Whether Matcher nodes handle migrations to their databases.
```

#### &emsp;period: ""
```
A time.ParseDuration parsable string

Determines how often updates for new security advisories will take place.

Defaults to 30 minutes.
```

#### &emsp;disable_updaters: ""
```
A "true" or "false" value

Whether to run background updates or not.
```

#### &emsp;update_retention: ""
```
An integer value 

Sets the number of update operations to retain between garbage collection cycles.
This should be set to a safe MAX value based on database size constraints. 

Defaults to 10

If a value of 0 is provided GC is disabled.
```

### updaters: \<object\>

```
Updaters provides configuration for the Matcher's update manager.
```

#### &emsp;sets: []string
```
A list of string values informing the update manager which Updaters to run.

If the value is nil the default set of Updaters will run:
    "alpine"
    "aws"
    "debian"
    "oracle"
    "photon"
    "pyupio"
    "rhel"
    "suse"
    "ubuntu"

If an empty list is provided zero updaters will run.
```

#### &emsp;config: {}
```
Provides configuration to specific updater sets.

A map keyed by the name of the updater set name containing a sub-object which will be provided to the updater set's constructor. 

A hypothetical  example:
  config:
    ubuntu:
      security_tracker_url: http://security.url
      ignore_distributions: 
        - cosmic
```

### notifier: \<object\>
```
Notifier provides Clair Notifier node configuration
```

#### &emsp;connstring: ""
```

A Postgres connection string.

Formats:
url: "postgres://pqgotest:password@localhost/pqgotest?sslmode=verify-full"
or
string: "user=pqgotest dbname=pqgotest sslmode=verify-full"
```

#### &emsp;migrations: false
```
A "true" or "false" value

Whether Notifier nodes handle migrations to their database.
```

#### &emsp;indexer_addr: ""
```
A string in <host>:<port> format where <host> can be an empty string.

A Notifier contacts an Indexer to create obtain manifests affected by vulnerabilities.
The location of this Indexer is required.
```

#### &emsp;matcher_addr: ""
```
A string in <host>:<port> format where <host> can be an empty string.

A Notifier contacts a Matcher to list update operations and acquire diffs.
The location of this Indexer is required.
```

#### &emsp;poll_interval: ""
```
A time.ParseDuration parsable string

The frequency at which the notifier will query at Matcher for Update Operations.
```

#### &emsp;delivery_interval: ""
```
A time.ParseDuration parsable string

The frequency at which the notifier attempt delivery of created or previously failed
notifications
```

#### &emsp;disable_summary: false
```
A boolean

Controls whether notifications should be summarized to one per manifest or not.
```

#### &emsp;webhook: \<object\>
```
Configures the notifier for webhook delivery
```
#### &emsp;&emsp;target: ""
```
URL where our webhook will be delivered

```
#### &emsp;&emsp;callback: ""
```
The callback url where notifications can be received
The notification will be appended to this url
This will typically be where the clair notifier is hosted
```
#### &emsp;&emsp;headers: ""
```
{ "header": [ "value" ] }

A map associating header names to a list of header values
```
#### &emsp;&emsp;signed: ""
```
A "true" or "false" value

If true the Notifier will use its internal key server to sign out going webhooks.
```

#### &emsp;amqp: \<object\>
```
Configures the notifier for AMQP delivery.
Note: Clair does not declare any AMQP components on its own.
All attempts to use an exchange or queue are passive only and will fail
The broker administrators should setup exchanges and queues ahead of time.
```

#### &emsp;&emsp;direct: ""
```
A "true" or "false" value

If true the Notifier will deliver individual notifications (not a callback) to the configured AMQP broker.
```

#### &emsp;&emsp;rollup: ""
```
Integer 0 or greater.

If direct is true this value will inform notifier how many notifications to send in a single direct delivery. 
For example if direct is set to true and rollup is set to 5 the notifier will deliver no more then 5 notifications in a single json payload to the broker.
```

#### &emsp;&emsp;exchange: \<object\>
```
The AMQP Exchange to connect to.
```

#### &emsp;&emsp;&emsp;name: ""
```
string value

The name of the exchange to connect to.
```

#### &emsp;&emsp;&emsp;type: ""
```
string value

The type of the exchange. Typically:
"direct"
"fanout"
"topic"
"headers"
```

#### &emsp;&emsp;&emsp;durability: false
```
bool value

Whether the configured queue is durable or not.
```

#### &emsp;&emsp;&emsp;auto_delete: false
```
bool value

Whether the configured queue uses an auto_delete policy.
```

#### &emsp;&emsp;&emsp;routing_key: ""
```
string value

The name of the routing key each notification will be sent with.
```

#### &emsp;&emsp;callback: ""
```
a URL string 

If direct is false this URL is provided in the notificaition callback sent to the broker.
This URL should point to Clair's notification API endpoint.
```

#### &emsp;&emsp;uris: []
```
list of URL string

A list of one or more AMQP brokers to connect to in priority order.
Clair will attempt to connect to the first one in the list and if this
fails will try any subsuquent in specified order.
```

#### &emsp;&emsp;tls: \<object\>
```
Configures TLS connection to AMQP broker
```

#### &emsp;&emsp;&emsp;root_ca: ""
```
string value

The filesystem path where a root CA can be read.
```

#### &emsp;&emsp;&emsp;cert: ""
```
string value

The filesystem path where a tls certificate can be read.
```

#### &emsp;&emsp;&emsp;key: ""
```
string value

The filesystem path where a tls private key can be read.
```

#### &emsp;stomp: \<object\>
```
Configures the notifier for STOMP delivery.
```

#### &emsp;&emsp;direct: ""
```
A "true" or "false" value

If true the Notifier will deliver individual notifications (not a callback) to the configured STOMP broker.
```

#### &emsp;&emsp;rollup: ""
```
Integer 0 or greater.

If direct is true this value will inform notifier how many notifications to send in a single direct delivery. 
For example if direct is set to true and rollup is set to 5 the notifier will deliver no more then 5 notifications in a single json payload to the broker.
```

#### &emsp;&emsp;callback: ""
```
a URL string 

If direct is false this URL is provided in the notificaition callback sent to the broker.
This URL should point to Clair's notification API endpoint.
```

#### &emsp;&emsp;destination: ""
```
a string value

The STOMP destination to deliver notifications to. 
```

#### &emsp;&emsp;uris: []
```
list of URL string

A list of one or more STOMP brokers to connect to in priority order.
Clair will attempt to connect to the first one in the list and if this
fails will try any subsuquent in specified order.
```

#### &emsp;&emsp;tls: \<object\>
```
Configures TLS connection to STOMP broker
```

#### &emsp;&emsp;&emsp;root_ca: ""
```
string value

The filesystem path where a root CA can be read.
```

#### &emsp;&emsp;&emsp;cert: ""
```
string value

The filesystem path where a tls certificate can be read.
```

#### &emsp;&emsp;&emsp;key: ""
```
string value

The filesystem path where a tls private key can be read.
```

#### &emsp;&emsp;&emsp;user: \<object\>
```
Configures login information for conneting to a STOMP broker
```

#### &emsp;&emsp;&emsp;login: ""
```
string value

The STOMP login to connect with.
```

#### &emsp;&emsp;&emsp;passcode: ""
```
string value

The STOMP passcode to connect with.
```

### auth: \<object\>
```
Defines ClairV4's external and intra-service JWT based authentication.

If multiple auth mechanisms are defined the Keyserver is preferred.
```

### &emsp;psk: \<object\>
```
Defines pre-shard-key authentication
```

#### &emsp;&emsp;key: ""
```
a string value

A shared base64 encoded key distributed between all parties signing and verifying JWTs.
```

#### &emsp;&emsp;iss: []string
```
a list of string value

A list of jwt issuers to verify. An empty list will accept any issuer in a jwt claim.
```

### &emsp;keyserver: \<object\>
```
Defines Quay keyserver authentication
```

#### &emsp;&emsp;api: ""
```
a string value

The API where Quay Keyserver can be reached.
```

#### &emsp;&emsp;intraservice: ""
```
a string value

A key shared between all Clair nodes for intra-service JWT authentication.
```

### trace: \<object\>
```
Defines distributed tracing configuration based on OpenTelemtry
```

#### &emsp;name: ""
```
a string value

The name of the application traces will belong to.
```

#### &emsp;probability: 0.0
```
a float value

The probabality a trace will occur
```

#### &emsp;Jaeger: \<object\>
```
Defines values for Jaeger tracing
```

#### &emsp;&emsp;agent: \<object\>
```
Defines values for a Jaeger agent
```

#### &emsp;&emsp;&emsp;endpoint: ""
```
a string value

An address in <host>:<post> syntax where the agent will deliver traces.
```

#### &emsp;&emsp;&emsp;collector: \<object\>
```
Defines values for a Jaeger collector
```

#### &emsp;&emsp;&emsp;endpoint: ""
```
a string value

An address in <host>:<post> syntax where the agent will deliver traces.
```

#### &emsp;&emsp;&emsp;username: ""
```
a string value
```

#### &emsp;&emsp;&emsp;passwordd: ""
```
a string value
```

#### &emsp;&emsp;service_name: ""
```
a string value
```

#### &emsp;&emsp;tags: {}
```
a mapping of a string to a string
```

#### &emsp;&emsp;buffer_max: 0
```
a integer value
```

### metrics: \<object\>
```
Defines distributed tracing configuration based on OpenTelemtry
```

#### &emsp;name: ""
```
a string value
```

### &emsp;prometheus: \<object\>
```
Defines distributed tracing configuration based on OpenTelemtry
```

#### &emsp;&emsp;endpoint: ""
```
a string value
```
