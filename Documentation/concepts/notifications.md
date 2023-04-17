# Notifications

ClairV4 implements a notification system.

The notifier service will keep track of new security database updates and inform an interested client if new or removed vulnerabilities affect an indexed manifest.

The interested client can subscribe to notifications via several mechanisms:
* Webhook delivery
* AMQP delivery
* STOMP delivery

Configuring the notifier is done via the yaml configuration.

See the "Notifier" object in our [config reference](../reference/config.md)

## A Notification

When the notifier becomes aware of new vulnerabilities affecting a previously indexed manifest, it will use the configured method(s) to issue notifications about the new changes. Any given notification expresses the **most severe** vulnerability discovered because of the change. This avoids creating a flurry of notifications for the same security database update.

Once a client receives a notification, it should issue a new request against the [matcher](../reference/matcher.md) to receive an up-to-date vulnerability report.

The notification schema is the JSON marshaled form of the following types:

```go
// Reason indicates the catalyst for a notification
type Reason string
const (
	Added   Reason = "added"
	Removed Reason = "removed"
	Changed Reason = "changed"
)
type Notification struct {
	ID            uuid.UUID        `json:"id"`
	Manifest      claircore.Digest `json:"manifest"`
	Reason        Reason           `json:"reason"`
	Vulnerability VulnSummary      `json:"vulnerability"`
}
type VulnSummary struct {
	Name           string                  `json:"name"`
	Description    string                  `json:"description"`
	Package        *claircore.Package      `json:"package,omitempty"`
	Distribution   *claircore.Distribution `json:"distribution,omitempty"`
	Repo           *claircore.Repository   `json:"repo,omitempty"`
	Severity       string                  `json:"severity"`
	FixedInVersion string                  `json:"fixed_in_version"`
	Links          string                  `json:"links"`
}
```

## Webhook Delivery
*See the "Notifier.Webhook" object in the [config reference](../reference/config.md) for complete configuration details.*

When you configure notifier for webhook delivery you provide the service with the following pieces of information:
* A target URL where the webhook will fire
* The callback URL where the notifier may be reached including its API path
    * e.g. "http://clair-notifier/notifier/api/v1/notification"

When the notifier has determined an updated security database has changed the affected status of an indexed manifest, it will deliver the following JSON body to the configured target:
```json
{
  "notification_id": {uuid_string},
  "callback": {url_to_notifications}
}
```

On receipt, the server can immediately browse to the URL provided in the callback field.

### Pagination

The URL returned in the callback field brings the client to a paginated result.

The callback endpoint specification follows:

```go
GET /notifier/api/v1/notification/{id}?[page_size=N][next=N]
{
  page: {
    size:    int,      // maximum number of notifications in the response
    next:   string, //  if present, the next id to fetch.
  }
  notifications: [ Notification… ] // array of notifications; max len == page.size
}
```
The GET callback request implements a simple bare-minimum paging mechanism.

The "page_size" url param controls how many notifications are returned in a single page.
If not provided a default of 500 is used.

The "next" url param informs Clair the next set of paged notifications to return. If not provided the 0th page is assumed.

A page object accompanying the notification list specifies "next" and "size" fields.

The "next" field returned in the page must be provided as the subsequent request's "next" url parameter to retrieve the next set of notifications.

The "size" field will simply echo back the request page_size parameter.

When the final page is served to the client the returned "page" data structure will not contain a "next" member.

Therefore the following loop is valid for obtaining all notifications for a notification id in pages of a specified size.

```
{ page, notifications } = http.Get("http://clairv4/notifier/api/v1/notification/{id}?page_size=1000")

while (page.Next != None) {
    { page, notifications } = http.Get("http://clairv4/notifier/api/v1/notification/{id}?next={page.Next},page_size=1000")
}
```

*Note: If the client specifies a custom page_size it must specify this page_size on every request for accurate responses.*

### Deleting Notifications

While not mandatory, the client may issue a delete of the notification via a DELETE method. See [api](../howto/api.md) to view the delete api.

Deleting a notification ID will clean up resources in the notifier quicker. Otherwise the notifier will wait a predetermined length of time before clearing delivered notifications from its database.

## AMQP Delivery
*See the "Notifier.AMQP" object in our [config reference](../reference/config.md) for complete configuration details.*

The notifier also supports delivering to an AMQP broker. With AMQP delivery you can control whether a callback is delivered to the broker or whether notifications are directly delivered to the queue.

This allows the developer of the AMQP consumer to determine the logic of notification processing.

Note that AMQP delivery only supports AMQP 0.x protocol (e.g. RabbitMQ). If you need to publish notifications on AMQP 1.x message queue (e.g. ActiveMQ), you can use STOMP delivery.

### Direct Delivery

If the notifier's configuration specifies `direct: true` for AMQP, notifications will be delivered directly to the configured exchange.

When `direct` is set, the `rollup` property may be set to instruct the notifier to send a max number of notifications in a single AMQP message. This allows a balance between size of the message and number of messages delivered to the queue.

## Testing and Development

The notifier has a testing mode enabled when it sees the "NOTIFIER_TEST_MODE" environment variable set. It can be set to any value as we only check to see if it exists.

When this environment variable is set, the notifier will begin sending fake notifications to the configured delivery mechanism every "poll_interval" interval. This provides an easy way to implement and test new or existing deliverers.

The notifier will run in this mode until the environment variable is cleared and the service is restarted.
