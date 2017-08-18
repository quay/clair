# Notifications

Notifications are a way for Clair to inform another service that changes to tracked vulnerabilities have occurred.
Because changes to vulnerabilities also contain the set of affected images, Clair sends only the name of the notification to another service, then depends on that service read and mark the notification as read using Clair's API.
Because notification data can require pagination, Clair should only send the name of a notification.
If a notification is not marked as read, Clair will resend notifications at a configured interval.

# Webhook

Notifications are an extensible component of Clair, but out of the box Clair supports [webhooks].
The webhooks look like the following:

```json
{
  "Notification": {
    "Name": "6e4ad270-4957-4242-b5ad-dad851379573"
  }
}
```

If you're interested in adding your own notification senders, read the documentation on [adding new drivers].

[webhooks]: https://en.wikipedia.org/wiki/Webhook
[adding new drivers]: /Documentation/drivers-and-data-sources.md#adding-new-drivers
