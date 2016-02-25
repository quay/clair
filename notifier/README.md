# Notifications

Notifications are a way for Clair to inform an endpoint that changes to tracked vulnerabilities have occurred.
Because notification data can require pagination, Clair should only send the name of a notification.
It is expected that the receiving endpoint calls the Clair API for reading notifications and marking them as read after being notified.
If the notification is never marked as read, Clair will continue attempting to send the same notification to the endpoint indefinitely.

## Webhook

Webhook is an out-of-the-box notifier that sends the following JSON object via an HTTP POST:

```json
{
  "Notification": {
    "Name": "6e4ad270-4957-4242-b5ad-dad851379573"
  }
}
```

## Custom Notifiers

Clair can also be compiled with custom notifiers by importing them in `main.go`.
Custom notifiers are any Go package that implements the `Notifier` interface and registers themselves with the `notifier` package.
Notifiers are registered in [init()] similar to drivers for Go's standard [database/sql] package.

[init()]: https://golang.org/doc/effective_go.html#init
[database/sql]: https://godoc.org/database/sql
