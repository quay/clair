# vim: set expandtab ts=2 sw=2:
include "oapi";

# Some helper functions:
def example_ref($id): ref("examples/\($id).json"); # Files are local at build time.
def responses($r):
{
  "200": {
    description: "Success",
    headers: {
      "Clair-Error": header_ref("Clair-Error"),
    },
  },
  "400": response_ref("bad_request"),
  "415": response_ref("unsupported_media_type"),
  default: response_ref("oops"),
} * $r
;

# Some variables:
"/notifier/api/v1" as $path_notif |
"/matcher/api/v1" as $path_match |
"/indexer/api/v1" as $path_index |

# The OpenAPI object:
{
  openapi: "3.1.0",
  info: {
    title: "Clair Container Analyzer",
    description: ([
      "Clair is a set of cooperating microservices which can index and match a container image's content with known vulnerabilities.",
      "",
      "**Note:** Any endpoints tagged \"internal\" are documented for completeness but are considered exempt from versioning.",
      ""] | join("\n") | sub("[[:space:]]*$"; "")),
    version: "1.2.0",
    contact: {
      name: "Clair Team",
      url: "http://github.com/quay/clair",
      email: "clair-devel@googlegroups.com",
    },
    license: {
      name: "Apache License 2.0",
      url: "http://www.apache.org/licenses/",
    }
  },
  externalDocs: { url: "https://quay.github.io/clair/" },
  tags: ({
    indexer: "Indexer service endpoints.\n\nThese are responsible for determining the contents of containers.",
    matcher: "Matcher service endpoints.\n\nThese are responsible for generating reports against current vulnerability data.",
    notifier: "Matcher service endpoints.\n\nThese are responsible for serving notifications.",
    internal: "These are internal endpoints, documented for completeness.\n\nThey are exempted from API stability guarentees.",
  } | to_entries | map({name: .key, description: .value}) ),
  paths: {
    "\($path_notif)/notification/{id}": {
      parameters: [ {
        in: "path",
        name: "id",
        required: true,
        schema: schema_ref("token"),
        description: "A notification ID returned by a callback"
      } ],
      delete: {
        operationId: "DeleteNotification",
        responses: responses({
          "200": { description: "Delete the notification referenced by the \"id\" parameter." },
        }),
      },
      get: {
        operationId: "GetNotification",
        parameters: [
          {
            in: "query",
            name: "page_size",
            schema: {
              type: "integer",
              default: 500,
            },
            description: "The maximum number of notifications to deliver in a single page."
          },
          {
            in: "query",
            name: "next",
            schema: schema_ref("token"),
            description: "The next page to fetch via id. Typically this number is provided on initial response in the \"page.next\" field. The first request should omit this field."
          }
        ],
        responses: responses({
          "200": {
            description: "A paginated list of notifications",
            content: contenttype("notification_page"),
          },
          "304": {
            description: "Not Modified",
          },
        })
      }
    },
    "\($path_index)/index_report": {
      post: {
        operationId: "Index",
        requestBody: {
          description: "Manifest to index.",
          required: true,
          content: contenttype("manifest"),
        },
        responses: (responses({
          "201": {
            description: "IndexReport created.\n\nClients may want to avoid reading the body if simply submitting the manifest for later vulnerability reporting.",
            content: contenttype("index_report"),
            headers: {
              Location: header_ref("Location"),
              Link: header_ref("Link"),
            },
            links: {
              retrieve: {
                operationId: "GetIndexReport",
                parameters: {
                  digest: "$request.body#/hash"
                },
              },
              delete: {
                operationId: "DeleteManifest",
                parameters: {
                  digest: "$request.body#/hash"
                },
              },
              report: {
                operationId: "GetVulnerabilityReport",
                parameters: {
                  digest: "$request.body#/hash"
                },
              },
            },
          },
          "412": {
            description: "Precondition Failed",
          },
        }) | del(.["200"])),
      },
      delete: {
        operationId: "DeleteManifests",
        requestBody: {
          description: "Array of manifest digests to delete.",
          required: true,
          content: contenttype("bulk_delete"),
        },
        responses: responses({
          "200": {
            description: "Successfully deleted manifests.",
            content: contenttype("bulk_delete"),
          },
        }),
      }
    },
    "\($path_index)/index_report/{digest}": {
      delete: {
        operationId: "DeleteManifest",
        responses: (responses({"204": {
            description: "Success",
        }}) |
          del(.["200"])),
      },
      get: {
        operationId: "GetIndexReport",
        responses: responses({
          "200": {
            description: "IndexReport retrieved",
            content: contenttype("index_report"),
          },
          "404": response_ref("not_found"),
        }),
      },
      parameters: [ param_ref("digest") ],
    },
    "\($path_index)/internal/affected_manifest": {
      post: {
        operationId: "AffectedManifests",
        requestBody: {
          description: "Array of vulnerability summaries to report on.",
          required: true,
          content: contenttype("vulnerability_summaries"),
        },
        responses: responses({
          "200": {
            description: "The list of manifests and the corresponding vulnerabilities.",
            content: contenttype("affected_manifests"),
          },
        }),
      },
    },
    "\($path_index)/index_state": {
      get: {
        operationId: "IndexState",
        responses: {
          "200": {
            description: "Indexer State",
            headers: {
              Etag: header_ref("Etag"),
            },
            content: contenttype("index_state"),
          },
          "304": {
            description: "Not Modified",
          },
        }
      }
    },
    "\($path_match)/vulnerability_report/{digest}": {
      get: {
        operationId: "GetVulnerabilityReport",
        responses: (responses({
          "201": {
            description: "Vulnerability Report Created",
            content: contenttype("vulnerability_report"),
          }
          ,
          "404": response_ref("not_found"),
        }) | del(.["200"])),
      },
      parameters: [ param_ref("digest") ],
    },
    "\($path_match)/internal/update_operation": {
      get: {
        operationId: "GetUpdateOperation",
        responses: responses({
          "200": {
            description: "Update Operations, keyed by updater.",
            content: contenttype("update_operations"),
          },
        }),
        parameters: [
          {
            in: "query",
            name: "kind",
            schema: {
              enum:["vulnerability", "enrichment"],
              default:"vulnerability",
            },
            description: "The \"kind\" of updaters to query."
          },
          {
            in: "query",
            name: "latest",
            schema: {
              type:"boolean",
              default: false
            },
            description: "Return only the latest Update Operations instead of all known Update Operations."
          }
        ],
      },
    },
    "\($path_match)/internal/update_operation/{digest}": {
      delete: {
        operationId: "DeleteUpdateOperation",
        responses: (responses({})),
      },
      parameters: [ param_ref("digest") ],
    },
    "\($path_match)/internal/update_diff": {
      get: {
        operationId: "GetUpdateDiff",
        responses: responses({
          "200": {
            description: "Changes between two Update Operations.",
            content: contenttype("update_diff"),
          },
        }),
        parameters: [
          {
            in: "query",
            name: "cur",
            schema: schema_ref("token"),
            description: "\"Current\" Update Operation ref."
          },
          {
            in: "query",
            name: "prev",
            required: true,
            schema: schema_ref("token"),
            description: "\"Previous\" Update Operation ref."
          }
        ],
      },
    },
  },
  security: [
    {},
    { PSK: [] }
  ],
  webhooks: {
    notification: {
      post: {
        tags: ["notifier"],
        description: "If configured, Clair will issue webhooks when notifications are available for retrieval.",
        requestBody: {
          content: contenttype("notification_webhook"),
        },
        responses: {
          "200": {
            description: "OK",
          },
        },
      },
    },
  },
  components: {
    schemas: {
      # Anything here will get overwritten by standalone JSON Schema objects
      # if the keys are duplicated.
      #
      # Generally, anything that goes in a response/request body should have a
      # schema over in the types directory.
      token: {
        type: "string",
        description: "An opaque token previously obtained from the service.",
      },
    },
    responses: {
      bad_request: {
        description: "Bad Request",
        content: contenttype("error"),
      },
      oops: {
        description: "Internal Server Error",
        content: contenttype("error"),
      },
      not_found: {
        description: "Not Found",
        content: contenttype("error"),
      },
      # Not expressible in OpenAPI:
      #method_not_allowed: {
      #  description: "Method Not Allowed",
      #  headers: {
      #    Allow: header_ref("Allow"),
      #  },
      #  content: contenttype("error"),
      #},
      unsupported_media_type: {
        description: "Unsupported Media Type",
        content: contenttype("error"),
      },
    },
    parameters: {
      digest: {
        description: "OCI-compatible digest of a referred object.",
        name: "digest",
        in: "path",
        schema: schema_ref("digest"),
        required: true,
      }
    },
    headers: {
      # Only used for 415 Method Not Allowed responses, which aren't expressible in OpenAPI.
      #Allow: {
      #  description: "TKTK",
      #  style: "simple",
      #  schema: { type: "string" },
      #  required: true,
      #},
      "Clair-Error": {
        description: "This is a trailer containing any errors encountered while writing the response.",
        style: "simple",
        schema: { type: "string" },
      },
      Etag: {
        description: "HTTP [ETag header](https://httpwg.org/specs/rfc9110.html#field.etag)",
        style: "simple",
        schema: { type: "string" }
      },
      Link: {
        description: "Web Linking [Link header](https://httpwg.org/specs/rfc8288.html#header)",
        style: "simple",
        schema: { type: "string" },
      },
      Location: {
        description: "HTTP [Location header](https://httpwg.org/specs/rfc9110.html#field.location)",
        style: "simple",
        required: true,
        schema: { type: "string" },
      },
    },
    securitySchemes: {
      PSK: {
        type: "http",
        scheme: "bearer",
        bearerFormat: "JWT with preshared key and allow-listed issuers",
        description: "Clair's authentication scheme.\n\nThis is a [JWT](https://datatracker.ietf.org/doc/html/rfc7519) signed with a configured pre-shared key containing an allowlisted `iss` claim.",
      },
    },
  },
}
|
# And now, a bunch of fixups:
def add_tags: # Match the path prefixes and add default tags.
  .paths |= with_entries(
    (
      if (.key|contains("internal")) then
        "internal"
      elif (.key|startswith($path_index)) then
        "indexer"
      elif (.key|startswith($path_match)) then
        "matcher"
      elif (.key|startswith($path_notif)) then
        "notifier"
      else
        ""
      end
    ) as $k |
    if ($k=="") then
      .
    else
      (.value[]|select(objects)) |= . + {
        tags: ((.tags//[]) + [$k]),
      }
    end
  )
;
def operation_metadata: # Slipstream some metadata into response objects.
  {
    AffectedManifests: {
      summary: "Retrieve Manifests Affected by a Vulnerability",
      description: "The provided vulnerability summaries are attempted to be run \"backwards\" through the indexer to produce a set of manifests.",
    },
    DeleteManifest: {
      summary: "Delete an Indexed Manifest",
      description: "Given a Manifest's content addressable hash, any data related to it will be removed it it exists.",
    },
    DeleteManifests: {
      summary: "Delete Indexed Manifests",
      description: "Given a Manifest's content addressable hash, any data related to it will be removed if it exists.",
    },
    DeleteNotification: {
      summary: "Delete a Notification Set",
      description: "Issues a delete of the provided notification ID and all associated notifications.\nAfter this delete clients will no longer be able to retrieve notifications.",
    },
    DeleteUpdateOperation: {
      summary: "Delete an Update Operation",
      description: "Issues a delete of the provided Update Operation ID and all associated data.\nAfter this delete clients will no longer be able to generate a diff against this Update Operation.",
    },
    GetIndexReport: {
      summary: "Retrieve the IndexReport for a Manifest",
      description: "Given a Manifest's content addressable hash, an IndexReport will be retrieved if it exists.",
    },
    GetNotification: {
      summary: "Retrieve Pages of a Notification Set",
      description: "By performing a GET with an id as a path parameter, the client will retrieve a paginated response of notification objects.",
    },
    GetUpdateDiff: {
      summary: "Retrieve Vulnerability Changes Between Two Update Operations",
      description: "Given IDs for two Update Operations, this will return the difference between them. This is used in the notification flow.",
    },
    GetUpdateOperation: {
      summary: "Retrieve Update Operations",
      description: "Retrive all known or just the latest Update Operations.",
    },
    GetVulnerabilityReport: {
      summary: "Retrieve a VulnerabilityReport for a Manifest",
      description: "Given a Manifest's content addressable hash a VulnerabilityReport will be created. The Manifest **must** have been Indexed first via the Index endpoint.",
    },
    Index: {
      summary: "Index a Manifest",
      description: "By submitting a Manifest object to this endpoint Clair will fetch the layers, scan each layer's contents, and provide an index of discovered packages, repository and distribution information.",
    },
    IndexState: {
      summary: "Report the Indexer's State",
      description: "The index state endpoint returns a json structure indicating the indexer's internal configuration state.\nA client may be interested in this as a signal that manifests may need to be re-indexed.",
    },
  } as $m |
  ( .paths[][] | select(objects) ) |= (
    .operationId as $id |
    ($m[$id]?) as $m |
    if ($m) then
      . + $m
    else
      .
    end
  )
;

sort_paths |
content_defaults |
add_tags |
operation_metadata |
cli_hints |
.
