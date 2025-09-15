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
      "**Note:** Any endpoints tagged \"internal\" or \"unstable\" are documented for completeness but are considered exempt from versioning.",
      ""] | join("\n") | sub("[[:space:]]*$"; "")),
    version: "1.2.0",
    contact: {
      name: "Clair Team",
      url: "http://github.com/quay/clair",
      email: "quay-devel@redhat.com",
    },
    license: {
      name: "Apache License 2.0",
      url: "http://www.apache.org/licenses/",
    }
  },
  externalDocs: {url: "https://quay.github.io/clair/"},
  tags: [
    { name: "indexer" },
    { name: "matcher" },
    { name: "notifier" },
    { name: "internal" },
    { name: "unstable" }
  ],
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
        responses: responses({"204": {description: "TODO"}}),
      },
      get: {
        operationId: "GetNotification",
        parameters: [
          {
            in: "query",
            name: "page_size",
            schema: {"type": "integer"},
            description: "The maximum number of notifications to deliver in a single page."
          },
          {
            in: "query",
            name: "next",
            schema: {"type": "string"},
            description: "The next page to fetch via id. Typically this number is provided on initial response in the \"page.next\" field. The first request should omit this field."
          }
        ],
        responses: responses({
          "200": {
            description: "A paginated list of notifications",
            content: contenttype("notification_page"),
          },
          "304": {
            description: "Not modified",
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
        tags: [ "internal", "unstable"],
        operationId: "AffectedManifests",
        responses: responses({
          "200": {
            description: "TODO",
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
      post: {
        tags: [ "internal", "unstable"],
        operationId: "UpdateOperation",
        responses: responses({
          "200": {
            description: "TODO",
            content: contenttype("affected_manifests"),
          },
        }),
      },
    },
    "\($path_match)/internal/update_diff": {
      get: {
        tags: [ "internal", "unstable"],
        operationId: "GetUpdateDiff",
        responses: responses({
          "200": {
            description: "TODO",
            content: contenttype("update_diff"),
          },
        }),
        parameters: [
          {
            in: "query",
            name: "cur",
            schema: schema_ref("token"),
            description: "TKTK"
          },
          {
            in: "query",
            name: "prev",
            schema: schema_ref("token"),
            description: "TKTK"
          }
        ],
      },
    },
  },
  security: [
    #{},
    #{"psk": []},
  ],
  webhooks: {
    notification: {
      post: {
        tags: ["notifier"],
        requestBody: {
          content: contenttype("notification"),
        },
        responses: {
          "200": {
            description: "TODO",
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
        "type": "string",
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
      #  schema: { "type": "string" },
      #  required: true,
      #},
      "Clair-Error": {
        description: "This is a trailer containing any errors encountered while writing the response.",
        style: "simple",
        schema: { "type": "string" },
      },
      Etag: {
        description: "HTTP [ETag header](https://httpwg.org/specs/rfc9110.html#field.etag)",
        style: "simple",
        schema: {"type": "string"}
      },
      Link: {
        description: "Web Linking [Link header](https://httpwg.org/specs/rfc8288.html#header)",
        style: "simple",
        schema: { "type": "string" },
      },
      Location: {
        description: "HTTP [Location header](https://httpwg.org/specs/rfc9110.html#field.location)",
        style: "simple",
        required: true,
        schema: { "type": "string" },
      },
    },
    securitySchemes: {
      psk: {
        "type": "http",
        scheme: "bearer",
        bearerFormat: "JWT with preshared key and allow-listed issuers",
        description: "Clair's authentication scheme.",
      },
    },
  },
}
|
# And now, a bunch of fixups:
def add_tags: # Match the path prefixes and add default tags.
  .paths |= with_entries(
    (
      if (.key|startswith($path_index)) then
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
      summary: "Retrieve the set of manifests affected by the provided vulnerabilities.",
      description: "",
    },
    DeleteManifest: {
      summary: "Delete the referenced manifest.",
      description: "Given a Manifest's content addressable hash, any data related to it will be removed it it exists.",
    },
    DeleteManifests: {
      summary: "Delete the referenced manifests.",
      description: "Given a Manifest's content addressable hash, any data related to it will be removed if it exists.",
    },
    DeleteNotification: {
      summary: "Delete the referenced notification set.",
      description: "Issues a delete of the provided notification id and all associated notifications.\nAfter this delete clients will no longer be able to retrieve notifications.",
    },
    GetIndexReport: {
      summary: "Retrieve the IndexReport for the referenced manifest.",
      description: "Given a Manifest's content addressable hash, an IndexReport will be retrieved if it exists.",
    },
    GetNotification: {
      summary: "Retrieve pages of the referenced notification set.",
      description: "By performing a GET with an id as a path parameter, the client will retrieve a paginated response of notification objects.",
    },
    GetVulnerabilityReport: {
      summary: "Retrieve a VulnerabilityReport for the referenced manifest.",
      description: "Given a Manifest's content addressable hash a VulnerabilityReport will be created. The Manifest **must** have been Indexed first via the Index endpoint.",
    },
    Index: {
      summary: "Index the contents of a Manifest",
      description: "By submitting a Manifest object to this endpoint Clair will fetch the layers, scan each layer's contents, and provide an index of discovered packages, repository and distribution information.",
    },
    IndexState: {
      summary: "Report the indexer's internal configuration and state.",
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
