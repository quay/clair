# Internal

Internal endpoints are underneath `/api/v1/internal` and are meant for
communication between Clair microservices. If Clair is operating in combo mode,
these endpoints may not exist. Any sort of API ingress should disallow clients
to talk to these endpoints.

## Updates

The `updates/` endpoints expose information about updater operations for use by the
notifier process.
