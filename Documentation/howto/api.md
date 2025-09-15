# API Definition

Clair provides its API definition via an OpenAPI specification. You can view our OpenAPI spec [here][openapi_v1].

The OpenAPI spec can be used in a variety of ways.
* Generating http clients for your application
* Validating data returned from Clair
* Importing into a rest client such as [Postman](https://learning.postman.com/docs/integrations/available-integrations/working-with-openAPI/)
* API documentation via [Swagger Editor](https://petstore.swagger.io/#/)

See [Testing Clair](./testing.md) to learn how the local dev tooling starts a local swagger editor. This is handy for making changes to the spec in real time.

See [API Reference](../reference/api.md) for a markdown rendered API reference.

[openapi_v1]: https://github.com/quay/clair/tree/main/httptransport/api/v1
