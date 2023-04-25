# Internal

Internal endpoints are underneath `/api/v1/internal` and are meant for
communication between Clair microservices. If Clair is operating in combo mode,
these endpoints may not exist. Any sort of API ingress should disallow clients
to talk to these endpoints.

We do not formally expose these APIs in our OpenAPI spec. 
Further information and usage is an effort left to the reader.

## Updates Diffs

The `update_diff/` endpoint exposes the api for diffing two update operations. 
This is used by the notifier to determine the added and removed vulnerabilities on security databsae update.

## Update Operation

The `update_operation` endpoint exposes the api for viewing updaters' activity. 
This is used by the notifier to determine if new updates have occurred and triggers an update diff to see what has changed.

## AffectedManifest

The `affected_manifest` endpoint exposes the api for retreiving affected manifests given a list of Vulnerabilities.
This is used by the notifier to determine the manifests that need to have a notification generated.
