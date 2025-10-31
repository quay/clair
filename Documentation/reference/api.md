---
title: Clair Container Analyzer v1.2.0
language_tabs:
  - python: Python
  - go: Golang
  - javascript: Javascript
language_clients:
  - python: ""
  - go: ""
  - javascript: ""
toc_footers:
  - <a href="https://quay.github.io/clair/">External documentation</a>
includes: []
search: false
highlight_theme: darkula
headingLevel: 2

---

<!-- Generator: Widdershins v4.0.1 -->

<h1 id="clair-container-analyzer">Clair Container Analyzer v1.2.0</h1>

> Scroll down for code samples, example requests and responses. Select a language for code samples from the tabs above or the mobile navigation menu.

Clair is a set of cooperating microservices which can index and match a container image's content with known vulnerabilities.

**Note:** Any endpoints tagged "internal" are documented for completeness but are considered exempt from versioning.

Email: <a href="mailto:clair-devel@googlegroups.com">Clair Team</a> Web: <a href="http://github.com/quay/clair">Clair Team</a> 
License: <a href="http://www.apache.org/licenses/">Apache License 2.0</a>

# Authentication

- HTTP Authentication, scheme: bearer Clair's authentication scheme.

This is a [JWT](https://datatracker.ietf.org/doc/html/rfc7519) signed with a configured pre-shared key containing an allowlisted `iss` claim.

<h1 id="clair-container-analyzer-indexer">indexer</h1>

Indexer service endpoints.

These are responsible for determining the contents of containers.

## Index a Manifest

<a id="opIdIndex"></a>

> Code samples

```python
import requests
headers = {
  'Content-Type': 'application/vnd.clair.manifest.v1+json',
  'Accept': 'application/vnd.clair.index_report.v1+json'
}

r = requests.post('/indexer/api/v1/index_report', headers = headers)

print(r.json())

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/vnd.clair.manifest.v1+json"},
        "Accept": []string{"application/vnd.clair.index_report.v1+json"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("POST", "/indexer/api/v1/index_report", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

```javascript
const inputBody = '{
  "hash": "sha256:fc84b5febd328eccaa913807716887b3eb5ed08bc22cc6933a9ebf82766725e3",
  "layers": [
    {
      "hash": "sha256:2f077db56abccc19f16f140f629ae98e904b4b7d563957a7fc319bd11b82ba36",
      "uri": "https://storage.example.com/blob/2f077db56abccc19f16f140f629ae98e904b4b7d563957a7fc319bd11b82ba36",
      "headers": {
        "Authoriztion": [
          "Bearer hunter2"
        ]
      }
    }
  ]
}';
const headers = {
  'Content-Type':'application/vnd.clair.manifest.v1+json',
  'Accept':'application/vnd.clair.index_report.v1+json'
};

fetch('/indexer/api/v1/index_report',
{
  method: 'POST',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

`POST /indexer/api/v1/index_report`

By submitting a Manifest object to this endpoint Clair will fetch the layers, scan each layer's contents, and provide an index of discovered packages, repository and distribution information.

> Body parameter

```json
{
  "hash": "sha256:fc84b5febd328eccaa913807716887b3eb5ed08bc22cc6933a9ebf82766725e3",
  "layers": [
    {
      "hash": "sha256:2f077db56abccc19f16f140f629ae98e904b4b7d563957a7fc319bd11b82ba36",
      "uri": "https://storage.example.com/blob/2f077db56abccc19f16f140f629ae98e904b4b7d563957a7fc319bd11b82ba36",
      "headers": {
        "Authoriztion": [
          "Bearer hunter2"
        ]
      }
    }
  ]
}
```

<h3 id="index-a-manifest-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[manifest](#schemamanifest)|true|Manifest to index.|

> Example responses

> 201 Response

```json
{
  "manifest_hash": null,
  "state": "string",
  "err": "string",
  "success": true,
  "packages": {},
  "distributions": {},
  "repository": {},
  "environments": {
    "property1": [],
    "property2": []
  }
}
```

<h3 id="index-a-manifest-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|201|[Created](https://tools.ietf.org/html/rfc7231#section-6.3.2)|IndexReport created.

Clients may want to avoid reading the body if simply submitting the manifest for later vulnerability reporting.|[index_report](#schemaindex_report)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad Request|[error](#schemaerror)|
|412|[Precondition Failed](https://tools.ietf.org/html/rfc7232#section-4.2)|Precondition Failed|None|
|415|[Unsupported Media Type](https://tools.ietf.org/html/rfc7231#section-6.5.13)|Unsupported Media Type|[error](#schemaerror)|
|default|Default|Internal Server Error|[error](#schemaerror)|

### Response Headers

|Status|Header|Type|Format|Description|
|---|---|---|---|---|
|201|Location|string||HTTP [Location header](https://httpwg.org/specs/rfc9110.html#field.location)|
|201|Link|string||Web Linking [Link header](https://httpwg.org/specs/rfc8288.html#header)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
None, PSK
</aside>

## Delete Indexed Manifests

<a id="opIdDeleteManifests"></a>

> Code samples

```python
import requests
headers = {
  'Content-Type': 'application/vnd.clair.bulk_delete.v1+json',
  'Accept': 'application/vnd.clair.bulk_delete.v1+json'
}

r = requests.delete('/indexer/api/v1/index_report', headers = headers)

print(r.json())

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/vnd.clair.bulk_delete.v1+json"},
        "Accept": []string{"application/vnd.clair.bulk_delete.v1+json"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("DELETE", "/indexer/api/v1/index_report", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

```javascript
const inputBody = '[
  "sha256:fc84b5febd328eccaa913807716887b3eb5ed08bc22cc6933a9ebf82766725e3"
]';
const headers = {
  'Content-Type':'application/vnd.clair.bulk_delete.v1+json',
  'Accept':'application/vnd.clair.bulk_delete.v1+json'
};

fetch('/indexer/api/v1/index_report',
{
  method: 'DELETE',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

`DELETE /indexer/api/v1/index_report`

Given a Manifest's content addressable hash, any data related to it will be removed if it exists.

> Body parameter

```json
[
  "sha256:fc84b5febd328eccaa913807716887b3eb5ed08bc22cc6933a9ebf82766725e3"
]
```

<h3 id="delete-indexed-manifests-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[bulk_delete](#schemabulk_delete)|true|Array of manifest digests to delete.|

> Example responses

> 200 Response

```json
[
  "sha256:fc84b5febd328eccaa913807716887b3eb5ed08bc22cc6933a9ebf82766725e3"
]
```

<h3 id="delete-indexed-manifests-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Successfully deleted manifests.|[bulk_delete](#schemabulk_delete)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad Request|[error](#schemaerror)|
|415|[Unsupported Media Type](https://tools.ietf.org/html/rfc7231#section-6.5.13)|Unsupported Media Type|[error](#schemaerror)|
|default|Default|Internal Server Error|[error](#schemaerror)|

### Response Headers

|Status|Header|Type|Format|Description|
|---|---|---|---|---|
|200|Clair-Error|string||This is a trailer containing any errors encountered while writing the response.|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
None, PSK
</aside>

## Delete an Indexed Manifest

<a id="opIdDeleteManifest"></a>

> Code samples

```python
import requests
headers = {
  'Accept': 'application/vnd.clair.error.v1+json'
}

r = requests.delete('/indexer/api/v1/index_report/{digest}', headers = headers)

print(r.json())

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/vnd.clair.error.v1+json"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("DELETE", "/indexer/api/v1/index_report/{digest}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

```javascript

const headers = {
  'Accept':'application/vnd.clair.error.v1+json'
};

fetch('/indexer/api/v1/index_report/{digest}',
{
  method: 'DELETE',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

`DELETE /indexer/api/v1/index_report/{digest}`

Given a Manifest's content addressable hash, any data related to it will be removed it it exists.

<h3 id="delete-an-indexed-manifest-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|digest|path|[digest](#schemadigest)|true|OCI-compatible digest of a referred object.|

> Example responses

> 400 Response

```json
{
  "code": "string",
  "message": "string"
}
```

<h3 id="delete-an-indexed-manifest-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|204|[No Content](https://tools.ietf.org/html/rfc7231#section-6.3.5)|Success|None|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad Request|[error](#schemaerror)|
|415|[Unsupported Media Type](https://tools.ietf.org/html/rfc7231#section-6.5.13)|Unsupported Media Type|[error](#schemaerror)|
|default|Default|Internal Server Error|[error](#schemaerror)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
None, PSK
</aside>

## Retrieve the IndexReport for a Manifest

<a id="opIdGetIndexReport"></a>

> Code samples

```python
import requests
headers = {
  'Accept': 'application/vnd.clair.index_report.v1+json'
}

r = requests.get('/indexer/api/v1/index_report/{digest}', headers = headers)

print(r.json())

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/vnd.clair.index_report.v1+json"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "/indexer/api/v1/index_report/{digest}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

```javascript

const headers = {
  'Accept':'application/vnd.clair.index_report.v1+json'
};

fetch('/indexer/api/v1/index_report/{digest}',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

`GET /indexer/api/v1/index_report/{digest}`

Given a Manifest's content addressable hash, an IndexReport will be retrieved if it exists.

<h3 id="retrieve-the-indexreport-for-a-manifest-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|digest|path|[digest](#schemadigest)|true|OCI-compatible digest of a referred object.|

> Example responses

> 200 Response

```json
{
  "manifest_hash": null,
  "state": "string",
  "err": "string",
  "success": true,
  "packages": {},
  "distributions": {},
  "repository": {},
  "environments": {
    "property1": [],
    "property2": []
  }
}
```

<h3 id="retrieve-the-indexreport-for-a-manifest-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|IndexReport retrieved|[index_report](#schemaindex_report)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad Request|[error](#schemaerror)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not Found|[error](#schemaerror)|
|415|[Unsupported Media Type](https://tools.ietf.org/html/rfc7231#section-6.5.13)|Unsupported Media Type|[error](#schemaerror)|
|default|Default|Internal Server Error|[error](#schemaerror)|

### Response Headers

|Status|Header|Type|Format|Description|
|---|---|---|---|---|
|200|Clair-Error|string||This is a trailer containing any errors encountered while writing the response.|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
None, PSK
</aside>

## Report the Indexer's State

<a id="opIdIndexState"></a>

> Code samples

```python
import requests
headers = {
  'Accept': 'application/vnd.clair.index_state.v1+json'
}

r = requests.get('/indexer/api/v1/index_state', headers = headers)

print(r.json())

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/vnd.clair.index_state.v1+json"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "/indexer/api/v1/index_state", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

```javascript

const headers = {
  'Accept':'application/vnd.clair.index_state.v1+json'
};

fetch('/indexer/api/v1/index_state',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

`GET /indexer/api/v1/index_state`

The index state endpoint returns a json structure indicating the indexer's internal configuration state.
A client may be interested in this as a signal that manifests may need to be re-indexed.

> Example responses

> 200 Response

```json
{
  "state": "string"
}
```

<h3 id="report-the-indexer's-state-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Indexer State|[index_state](#schemaindex_state)|
|304|[Not Modified](https://tools.ietf.org/html/rfc7232#section-4.1)|Not Modified|None|

### Response Headers

|Status|Header|Type|Format|Description|
|---|---|---|---|---|
|200|Etag|string||HTTP [ETag header](https://httpwg.org/specs/rfc9110.html#field.etag)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
None, PSK
</aside>

<h1 id="clair-container-analyzer-matcher">matcher</h1>

Matcher service endpoints.

These are responsible for generating reports against current vulnerability data.

## Retrieve a VulnerabilityReport for a Manifest

<a id="opIdGetVulnerabilityReport"></a>

> Code samples

```python
import requests
headers = {
  'Accept': 'application/vnd.clair.vulnerability_report.v1+json'
}

r = requests.get('/matcher/api/v1/vulnerability_report/{digest}', headers = headers)

print(r.json())

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/vnd.clair.vulnerability_report.v1+json"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "/matcher/api/v1/vulnerability_report/{digest}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

```javascript

const headers = {
  'Accept':'application/vnd.clair.vulnerability_report.v1+json'
};

fetch('/matcher/api/v1/vulnerability_report/{digest}',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

`GET /matcher/api/v1/vulnerability_report/{digest}`

Given a Manifest's content addressable hash a VulnerabilityReport will be created. The Manifest **must** have been Indexed first via the Index endpoint.

<h3 id="retrieve-a-vulnerabilityreport-for-a-manifest-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|digest|path|[digest](#schemadigest)|true|OCI-compatible digest of a referred object.|

> Example responses

> 201 Response

```json
{
  "manifest_hash": null,
  "packages": {},
  "distributions": {},
  "repository": {},
  "environments": {
    "property1": [],
    "property2": []
  },
  "vulnerabilities": {},
  "package_vulnerabilities": {
    "property1": [
      "string"
    ],
    "property2": [
      "string"
    ]
  },
  "enrichments": {
    "property1": [],
    "property2": []
  }
}
```

<h3 id="retrieve-a-vulnerabilityreport-for-a-manifest-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|201|[Created](https://tools.ietf.org/html/rfc7231#section-6.3.2)|Vulnerability Report Created|[vulnerability_report](#schemavulnerability_report)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad Request|[error](#schemaerror)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not Found|[error](#schemaerror)|
|415|[Unsupported Media Type](https://tools.ietf.org/html/rfc7231#section-6.5.13)|Unsupported Media Type|[error](#schemaerror)|
|default|Default|Internal Server Error|[error](#schemaerror)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
None, PSK
</aside>

<h1 id="clair-container-analyzer-notifier">notifier</h1>

Matcher service endpoints.

These are responsible for serving notifications.

## Delete a Notification Set

<a id="opIdDeleteNotification"></a>

> Code samples

```python
import requests
headers = {
  'Accept': 'application/vnd.clair.error.v1+json'
}

r = requests.delete('/notifier/api/v1/notification/{id}', headers = headers)

print(r.json())

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/vnd.clair.error.v1+json"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("DELETE", "/notifier/api/v1/notification/{id}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

```javascript

const headers = {
  'Accept':'application/vnd.clair.error.v1+json'
};

fetch('/notifier/api/v1/notification/{id}',
{
  method: 'DELETE',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

`DELETE /notifier/api/v1/notification/{id}`

Issues a delete of the provided notification ID and all associated notifications.
After this delete clients will no longer be able to retrieve notifications.

<h3 id="delete-a-notification-set-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|id|path|[token](#schematoken)|true|A notification ID returned by a callback|

> Example responses

> 400 Response

```json
{
  "code": "string",
  "message": "string"
}
```

<h3 id="delete-a-notification-set-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Delete the notification referenced by the "id" parameter.|None|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad Request|[error](#schemaerror)|
|415|[Unsupported Media Type](https://tools.ietf.org/html/rfc7231#section-6.5.13)|Unsupported Media Type|[error](#schemaerror)|
|default|Default|Internal Server Error|[error](#schemaerror)|

### Response Headers

|Status|Header|Type|Format|Description|
|---|---|---|---|---|
|200|Clair-Error|string||This is a trailer containing any errors encountered while writing the response.|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
None, PSK
</aside>

## Retrieve Pages of a Notification Set

<a id="opIdGetNotification"></a>

> Code samples

```python
import requests
headers = {
  'Accept': 'application/vnd.clair.notification_page.v1+json'
}

r = requests.get('/notifier/api/v1/notification/{id}', headers = headers)

print(r.json())

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/vnd.clair.notification_page.v1+json"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "/notifier/api/v1/notification/{id}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

```javascript

const headers = {
  'Accept':'application/vnd.clair.notification_page.v1+json'
};

fetch('/notifier/api/v1/notification/{id}',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

`GET /notifier/api/v1/notification/{id}`

By performing a GET with an id as a path parameter, the client will retrieve a paginated response of notification objects.

<h3 id="retrieve-pages-of-a-notification-set-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|page_size|query|integer|false|The maximum number of notifications to deliver in a single page.|
|next|query|[token](#schematoken)|false|The next page to fetch via id. Typically this number is provided on initial response in the "page.next" field. The first request should omit this field.|
|id|path|[token](#schematoken)|true|A notification ID returned by a callback|

> Example responses

> 200 Response

```json
{
  "page": {
    "size": 100,
    "next": "1b4d0db2-e757-4150-bbbb-543658144205"
  },
  "notifications": [
    {
      "id": "5e4b387e-88d3-4364-86fd-063447a6fad2",
      "manifest": "sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a",
      "reason": "added",
      "vulnerability": {
        "name": "CVE-2009-5155",
        "fixed_in_version": "v0.0.1",
        "links": "http://example.com/CVE-2009-5155",
        "description": "In the GNU C Library (aka glibc or libc6) before 2.28, parse_reg_exp in posix/regcomp.c misparses alternatives, which allows attackers to cause a denial of service (assertion failure and application exit) or trigger an incorrect result by attempting a regular-expression match.\"",
        "normalized_severity": "Unknown",
        "package": {
          "id": "10",
          "name": "libapt-pkg5.0",
          "version": "1.6.11",
          "kind": "BINARY",
          "arch": "x86",
          "source": {
            "id": "9",
            "name": "apt",
            "version": "1.6.11",
            "kind": "SOURCE",
            "source": null
          }
        },
        "distribution": {
          "id": "1",
          "did": "ubuntu",
          "name": "Ubuntu",
          "version": "18.04.3 LTS (Bionic Beaver)",
          "version_code_name": "bionic",
          "version_id": "18.04",
          "pretty_name": "Ubuntu 18.04.3 LTS"
        }
      }
    }
  ]
}
```

<h3 id="retrieve-pages-of-a-notification-set-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|A paginated list of notifications|[notification_page](#schemanotification_page)|
|304|[Not Modified](https://tools.ietf.org/html/rfc7232#section-4.1)|Not Modified|None|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad Request|[error](#schemaerror)|
|415|[Unsupported Media Type](https://tools.ietf.org/html/rfc7231#section-6.5.13)|Unsupported Media Type|[error](#schemaerror)|
|default|Default|Internal Server Error|[error](#schemaerror)|

### Response Headers

|Status|Header|Type|Format|Description|
|---|---|---|---|---|
|200|Clair-Error|string||This is a trailer containing any errors encountered while writing the response.|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
None, PSK
</aside>

<h1 id="clair-container-analyzer-internal">internal</h1>

These are internal endpoints, documented for completeness.

They are exempted from API stability guarentees.

## Retrieve Manifests Affected by a Vulnerability

<a id="opIdAffectedManifests"></a>

> Code samples

```python
import requests
headers = {
  'Content-Type': 'application/vnd.clair.vulnerability_summaries.v1+json',
  'Accept': 'application/vnd.clair.affected_manifests.v1+json'
}

r = requests.post('/indexer/api/v1/internal/affected_manifest', headers = headers)

print(r.json())

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Content-Type": []string{"application/vnd.clair.vulnerability_summaries.v1+json"},
        "Accept": []string{"application/vnd.clair.affected_manifests.v1+json"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("POST", "/indexer/api/v1/internal/affected_manifest", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

```javascript
const inputBody = '[]';
const headers = {
  'Content-Type':'application/vnd.clair.vulnerability_summaries.v1+json',
  'Accept':'application/vnd.clair.affected_manifests.v1+json'
};

fetch('/indexer/api/v1/internal/affected_manifest',
{
  method: 'POST',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

`POST /indexer/api/v1/internal/affected_manifest`

The provided vulnerability summaries are attempted to be run "backwards" through the indexer to produce a set of manifests.

> Body parameter

```json
[]
```

<h3 id="retrieve-manifests-affected-by-a-vulnerability-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[vulnerability_summaries](#schemavulnerability_summaries)|true|Array of vulnerability summaries to report on.|

> Example responses

> 200 Response

```json
{
  "vulnerabilities": {
    "42": {
      "id": "42"
    }
  },
  "vulnerable_manifests": {
    "sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b": [
      "42"
    ]
  }
}
```

<h3 id="retrieve-manifests-affected-by-a-vulnerability-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|The list of manifests and the corresponding vulnerabilities.|[affected_manifests](#schemaaffected_manifests)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad Request|[error](#schemaerror)|
|415|[Unsupported Media Type](https://tools.ietf.org/html/rfc7231#section-6.5.13)|Unsupported Media Type|[error](#schemaerror)|
|default|Default|Internal Server Error|[error](#schemaerror)|

### Response Headers

|Status|Header|Type|Format|Description|
|---|---|---|---|---|
|200|Clair-Error|string||This is a trailer containing any errors encountered while writing the response.|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
None, PSK
</aside>

## Retrieve Vulnerability Changes Between Two Update Operations

<a id="opIdGetUpdateDiff"></a>

> Code samples

```python
import requests
headers = {
  'Accept': 'application/vnd.clair.update_diff.v1+json'
}

r = requests.get('/matcher/api/v1/internal/update_diff', params={
  'prev': 'string'
}, headers = headers)

print(r.json())

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/vnd.clair.update_diff.v1+json"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "/matcher/api/v1/internal/update_diff", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

```javascript

const headers = {
  'Accept':'application/vnd.clair.update_diff.v1+json'
};

fetch('/matcher/api/v1/internal/update_diff?prev=string',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

`GET /matcher/api/v1/internal/update_diff`

Given IDs for two Update Operations, this will return the difference between them. This is used in the notification flow.

<h3 id="retrieve-vulnerability-changes-between-two-update-operations-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|cur|query|[token](#schematoken)|false|"Current" Update Operation ref.|
|prev|query|[token](#schematoken)|true|"Previous" Update Operation ref.|

> Example responses

> 200 Response

```json
{
  "prev": null,
  "cur": null,
  "added": [],
  "removed": []
}
```

<h3 id="retrieve-vulnerability-changes-between-two-update-operations-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Changes between two Update Operations.|[update_diff](#schemaupdate_diff)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad Request|[error](#schemaerror)|
|415|[Unsupported Media Type](https://tools.ietf.org/html/rfc7231#section-6.5.13)|Unsupported Media Type|[error](#schemaerror)|
|default|Default|Internal Server Error|[error](#schemaerror)|

### Response Headers

|Status|Header|Type|Format|Description|
|---|---|---|---|---|
|200|Clair-Error|string||This is a trailer containing any errors encountered while writing the response.|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
None, PSK
</aside>

## Retrieve Update Operations

<a id="opIdGetUpdateOperation"></a>

> Code samples

```python
import requests
headers = {
  'Accept': 'application/vnd.clair.update_operations.v1+json'
}

r = requests.get('/matcher/api/v1/internal/update_operation', headers = headers)

print(r.json())

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/vnd.clair.update_operations.v1+json"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "/matcher/api/v1/internal/update_operation", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

```javascript

const headers = {
  'Accept':'application/vnd.clair.update_operations.v1+json'
};

fetch('/matcher/api/v1/internal/update_operation',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

`GET /matcher/api/v1/internal/update_operation`

Retrive all known or just the latest Update Operations.

<h3 id="retrieve-update-operations-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|kind|query|any|false|The "kind" of updaters to query.|
|latest|query|boolean|false|Return only the latest Update Operations instead of all known Update Operations.|

#### Enumerated Values

|Parameter|Value|
|---|---|
|kind|vulnerability|
|kind|enrichment|

> Example responses

> 200 Response

```json
{
  "property1": [],
  "property2": []
}
```

<h3 id="retrieve-update-operations-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Update Operations, keyed by updater.|[update_operations](#schemaupdate_operations)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad Request|[error](#schemaerror)|
|415|[Unsupported Media Type](https://tools.ietf.org/html/rfc7231#section-6.5.13)|Unsupported Media Type|[error](#schemaerror)|
|default|Default|Internal Server Error|[error](#schemaerror)|

### Response Headers

|Status|Header|Type|Format|Description|
|---|---|---|---|---|
|200|Clair-Error|string||This is a trailer containing any errors encountered while writing the response.|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
None, PSK
</aside>

## Delete an Update Operation

<a id="opIdDeleteUpdateOperation"></a>

> Code samples

```python
import requests
headers = {
  'Accept': 'application/vnd.clair.error.v1+json'
}

r = requests.delete('/matcher/api/v1/internal/update_operation/{digest}', headers = headers)

print(r.json())

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/vnd.clair.error.v1+json"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("DELETE", "/matcher/api/v1/internal/update_operation/{digest}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

```javascript

const headers = {
  'Accept':'application/vnd.clair.error.v1+json'
};

fetch('/matcher/api/v1/internal/update_operation/{digest}',
{
  method: 'DELETE',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

`DELETE /matcher/api/v1/internal/update_operation/{digest}`

Issues a delete of the provided Update Operation ID and all associated data.
After this delete clients will no longer be able to generate a diff against this Update Operation.

<h3 id="delete-an-update-operation-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|digest|path|[digest](#schemadigest)|true|OCI-compatible digest of a referred object.|

> Example responses

> 400 Response

```json
{
  "code": "string",
  "message": "string"
}
```

<h3 id="delete-an-update-operation-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Success|None|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad Request|[error](#schemaerror)|
|415|[Unsupported Media Type](https://tools.ietf.org/html/rfc7231#section-6.5.13)|Unsupported Media Type|[error](#schemaerror)|
|default|Default|Internal Server Error|[error](#schemaerror)|

### Response Headers

|Status|Header|Type|Format|Description|
|---|---|---|---|---|
|200|Clair-Error|string||This is a trailer containing any errors encountered while writing the response.|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
None, PSK
</aside>

# Schemas

<h2 id="tocS_token">token</h2>
<!-- backwards compatibility -->
<a id="schematoken"></a>
<a id="schema_token"></a>
<a id="tocStoken"></a>
<a id="tocstoken"></a>

```json
"string"

```

An opaque token previously obtained from the service.

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|string|false|none|An opaque token previously obtained from the service.|

<h2 id="tocS_affected_manifests">affected_manifests</h2>
<!-- backwards compatibility -->
<a id="schemaaffected_manifests"></a>
<a id="schema_affected_manifests"></a>
<a id="tocSaffected_manifests"></a>
<a id="tocsaffected_manifests"></a>

```json
{
  "vulnerabilities": {
    "42": {
      "id": "42"
    }
  },
  "vulnerable_manifests": {
    "sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b": [
      "42"
    ]
  }
}

```

Affected Manifests

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|vulnerabilities|object|true|none|Vulnerability objects.|
|» **additionalProperties**|[vulnerability.schema.json](#schemavulnerability.schema.json)|false|none|none|
|vulnerable_manifests|object|true|none|Mapping of manifest digests to vulnerability identifiers.|
|» **additionalProperties**|[string]|false|none|none|

<h2 id="tocS_bulk_delete">bulk_delete</h2>
<!-- backwards compatibility -->
<a id="schemabulk_delete"></a>
<a id="schema_bulk_delete"></a>
<a id="tocSbulk_delete"></a>
<a id="tocsbulk_delete"></a>

```json
[
  "sha256:fc84b5febd328eccaa913807716887b3eb5ed08bc22cc6933a9ebf82766725e3"
]

```

Bulk Delete

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|Bulk Delete|[[digest.schema.json](#schemadigest.schema.json)]|false|none|Array of manifest digests to delete from the system.|

<h2 id="tocS_cpe">cpe</h2>
<!-- backwards compatibility -->
<a id="schemacpe"></a>
<a id="schema_cpe"></a>
<a id="tocScpe"></a>
<a id="tocscpe"></a>

```json
"cpe:/a:microsoft:internet_explorer:8.0.6001:beta"

```

Common Platform Enumeration Name

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|Common Platform Enumeration Name|any|false|none|This is a CPE Name in either v2.2 "URI" form or v2.3 "Formatted String" form.|

oneOf

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|string|false|none|This is the CPE 2.2 regexp: https://cpe.mitre.org/specification/2.2/cpe-language_2.2.xsd|

xor

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|string|false|none|This is the CPE 2.3 regexp: https://csrc.nist.gov/schema/cpe/2.3/cpe-naming_2.3.xsd|

<h2 id="tocS_digest">digest</h2>
<!-- backwards compatibility -->
<a id="schemadigest"></a>
<a id="schema_digest"></a>
<a id="tocSdigest"></a>
<a id="tocsdigest"></a>

```json
"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"

```

Digest

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|Digest|string|false|none|A digest acts as a content identifier, enabling content addressability.|

anyOf

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|string|false|none|SHA256|

or

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|string|false|none|SHA512|

or

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|string|false|none|BLAKE3<br><br>**Currently not implemented.**|

<h2 id="tocS_distribution">distribution</h2>
<!-- backwards compatibility -->
<a id="schemadistribution"></a>
<a id="schema_distribution"></a>
<a id="tocSdistribution"></a>
<a id="tocsdistribution"></a>

```json
{
  "id": "1",
  "did": "ubuntu",
  "name": "Ubuntu",
  "version": "18.04.3 LTS (Bionic Beaver)",
  "version_code_name": "bionic",
  "version_id": "18.04",
  "pretty_name": "Ubuntu 18.04.3 LTS"
}

```

Distribution

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|id|string|true|none|Unique ID for this Distribution. May be unique to the response document, not the whole system.|
|did|string|false|none|A lower-case string (no spaces or other characters outside of 0–9, a–z, ".", "_", and "-") identifying the operating system, excluding any version information and suitable for processing by scripts or usage in generated filenames.|
|name|string|false|none|A string identifying the operating system.|
|version|string|false|none|A string identifying the operating system version, excluding any OS name information, possibly including a release code name, and suitable for presentation to the user.|
|version_code_name|string|false|none|A lower-case string (no spaces or other characters outside of 0–9, a–z, ".", "_", and "-") identifying the operating system release code name, excluding any OS name information or release version, and suitable for processing by scripts or usage in generated filenames.|
|version_id|string|false|none|A lower-case string (mostly numeric, no spaces or other characters outside of 0–9, a–z, ".", "_", and "-") identifying the operating system version, excluding any OS name information or release code name.|
|arch|string|false|none|A string identifying the OS architecture.|
|cpe|[cpe.schema.json](#schemacpe.schema.json)|false|none|Common Platform Enumeration name.|
|pretty_name|string|false|none|A pretty operating system name in a format suitable for presentation to the user.|

<h2 id="tocS_environment">environment</h2>
<!-- backwards compatibility -->
<a id="schemaenvironment"></a>
<a id="schema_environment"></a>
<a id="tocSenvironment"></a>
<a id="tocsenvironment"></a>

```json
{
  "value": {
    "package_db": "var/lib/dpkg/status",
    "introduced_in": "sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a",
    "distribution_id": "1"
  }
}

```

Environment

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|package_db|string|false|none|The database the associated Package was discovered in.|
|distribution_id|string|false|none|The ID of the Distribution of the associated Package.|
|introduced_in|[digest.schema.json](#schemadigest.schema.json)|false|none|The Layer the associated Package was introduced in.|
|repository_ids|[string]|false|none|The IDs of the Repositories of the associated Package.|

<h2 id="tocS_error">error</h2>
<!-- backwards compatibility -->
<a id="schemaerror"></a>
<a id="schema_error"></a>
<a id="tocSerror"></a>
<a id="tocserror"></a>

```json
{
  "code": "string",
  "message": "string"
}

```

Error

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|code|string|false|none|a code for this particular error|
|message|string|true|none|a message with further detail|

<h2 id="tocS_index_report">index_report</h2>
<!-- backwards compatibility -->
<a id="schemaindex_report"></a>
<a id="schema_index_report"></a>
<a id="tocSindex_report"></a>
<a id="tocsindex_report"></a>

```json
{
  "manifest_hash": null,
  "state": "string",
  "err": "string",
  "success": true,
  "packages": {},
  "distributions": {},
  "repository": {},
  "environments": {
    "property1": [],
    "property2": []
  }
}

```

Index Report

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|manifest_hash|[digest.schema.json](#schemadigest.schema.json)|true|none|The Manifest's digest.|
|state|string|true|none|The current state of the index operation|
|err|string|false|none|An error message on event of unsuccessful index|
|success|boolean|true|none|A bool indicating succcessful index|
|packages|object|false|none|A map of Package objects indexed by a document-local identifier.|
|» **additionalProperties**|[package.schema.json](#schemapackage.schema.json)|false|none|none|
|distributions|object|false|none|A map of Distribution objects indexed by a document-local identifier.|
|» **additionalProperties**|[distribution.schema.json](#schemadistribution.schema.json)|false|none|none|
|repository|object|false|none|A map of Repository objects indexed by a document-local identifier.|
|» **additionalProperties**|[repository.schema.json](#schemarepository.schema.json)|false|none|none|
|environments|object|false|none|A map of Environment arrays indexed by a Package's identifier.|
|» **additionalProperties**|[[environment.schema.json](#schemaenvironment.schema.json)]|false|none|none|

<h2 id="tocS_index_state">index_state</h2>
<!-- backwards compatibility -->
<a id="schemaindex_state"></a>
<a id="schema_index_state"></a>
<a id="tocSindex_state"></a>
<a id="tocsindex_state"></a>

```json
{
  "state": "string"
}

```

Index State

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|state|string|true|none|an opaque token|

<h2 id="tocS_layer">layer</h2>
<!-- backwards compatibility -->
<a id="schemalayer"></a>
<a id="schema_layer"></a>
<a id="tocSlayer"></a>
<a id="tocslayer"></a>

```json
{
  "hash": null,
  "uri": "string",
  "headers": {},
  "media_type": "string"
}

```

Layer

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|hash|[digest.schema.json](#schemadigest.schema.json)|true|none|Digest of the layer blob.|
|uri|string|true|none|A URI indicating where the layer blob can be downloaded from.|
|headers|object|false|none|Any additional HTTP-style headers needed for requesting layers.|
|» ^[a-zA-Z0-9\-_]+$|[string]|false|none|none|
|media_type|string|false|none|The OCI Layer media type for this layer.|

<h2 id="tocS_manifest">manifest</h2>
<!-- backwards compatibility -->
<a id="schemamanifest"></a>
<a id="schema_manifest"></a>
<a id="tocSmanifest"></a>
<a id="tocsmanifest"></a>

```json
{
  "hash": "sha256:fc84b5febd328eccaa913807716887b3eb5ed08bc22cc6933a9ebf82766725e3",
  "layers": [
    {
      "hash": "sha256:2f077db56abccc19f16f140f629ae98e904b4b7d563957a7fc319bd11b82ba36",
      "uri": "https://storage.example.com/blob/2f077db56abccc19f16f140f629ae98e904b4b7d563957a7fc319bd11b82ba36",
      "headers": {
        "Authoriztion": [
          "Bearer hunter2"
        ]
      }
    }
  ]
}

```

Manifest

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|hash|[digest.schema.json](#schemadigest.schema.json)|true|none|The OCI Image Manifest's digest.<br><br>This is used as an identifier throughout the system. This **SHOULD** be the same as the OCI Image Manifest's digest, but this is not enforced.|
|layers|[[layer.schema.json](#schemalayer.schema.json)]|false|none|The OCI Layers making up the Image, in order.|

<h2 id="tocS_normalized_severity">normalized_severity</h2>
<!-- backwards compatibility -->
<a id="schemanormalized_severity"></a>
<a id="schema_normalized_severity"></a>
<a id="tocSnormalized_severity"></a>
<a id="tocsnormalized_severity"></a>

```json
"Unknown"

```

Normalized Severity

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|Normalized Severity|any|false|none|Standardized severity values.|

#### Enumerated Values

|Property|Value|
|---|---|
|Normalized Severity|Unknown|
|Normalized Severity|Negligible|
|Normalized Severity|Low|
|Normalized Severity|Medium|
|Normalized Severity|High|
|Normalized Severity|Critical|

<h2 id="tocS_notification_page">notification_page</h2>
<!-- backwards compatibility -->
<a id="schemanotification_page"></a>
<a id="schema_notification_page"></a>
<a id="tocSnotification_page"></a>
<a id="tocsnotification_page"></a>

```json
{
  "page": {
    "size": 100,
    "next": "1b4d0db2-e757-4150-bbbb-543658144205"
  },
  "notifications": [
    {
      "id": "5e4b387e-88d3-4364-86fd-063447a6fad2",
      "manifest": "sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a",
      "reason": "added",
      "vulnerability": {
        "name": "CVE-2009-5155",
        "fixed_in_version": "v0.0.1",
        "links": "http://example.com/CVE-2009-5155",
        "description": "In the GNU C Library (aka glibc or libc6) before 2.28, parse_reg_exp in posix/regcomp.c misparses alternatives, which allows attackers to cause a denial of service (assertion failure and application exit) or trigger an incorrect result by attempting a regular-expression match.\"",
        "normalized_severity": "Unknown",
        "package": {
          "id": "10",
          "name": "libapt-pkg5.0",
          "version": "1.6.11",
          "kind": "BINARY",
          "arch": "x86",
          "source": {
            "id": "9",
            "name": "apt",
            "version": "1.6.11",
            "kind": "SOURCE",
            "source": null
          }
        },
        "distribution": {
          "id": "1",
          "did": "ubuntu",
          "name": "Ubuntu",
          "version": "18.04.3 LTS (Bionic Beaver)",
          "version_code_name": "bionic",
          "version_id": "18.04",
          "pretty_name": "Ubuntu 18.04.3 LTS"
        }
      }
    }
  ]
}

```

Notification Page

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|page|object|true|none|An object informing the client the next page to retrieve.|
|» size|integer|true|none|The number of notifications contained in this page.|
|» next|string|false|none|The identififer to pass into the "next" parameter of a future GetNotification request.<br><br>If not present, there are no additional pages.|
|notifications|[[notification.schema.json](#schemanotification.schema.json)]|true|none|Notifications within this page.|

<h2 id="tocS_notification">notification</h2>
<!-- backwards compatibility -->
<a id="schemanotification"></a>
<a id="schema_notification"></a>
<a id="tocSnotification"></a>
<a id="tocsnotification"></a>

```json
{
  "id": "string",
  "manifest": null,
  "reason": "added",
  "vulnerability": null
}

```

Notification

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|id|string|true|none|Unique identifier for this notification.|
|manifest|[digest.schema.json](#schemadigest.schema.json)|true|none|The digest of the manifest affected by the provided vulnerability.|
|reason|any|true|none|The reason for the notifcation.|
|vulnerability|[vulnerability_summary.schema.json](#schemavulnerability_summary.schema.json)|true|none|none|

#### Enumerated Values

|Property|Value|
|---|---|
|reason|added|
|reason|removed|

<h2 id="tocS_notification_webhook">notification_webhook</h2>
<!-- backwards compatibility -->
<a id="schemanotification_webhook"></a>
<a id="schema_notification_webhook"></a>
<a id="tocSnotification_webhook"></a>
<a id="tocsnotification_webhook"></a>

```json
{
  "notification_id": "string",
  "callback": "http://example.com"
}

```

Notification Webhook

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|notification_id|string|true|none|Unique identifier for this notification.|
|callback|string(uri)|true|none|A URL to retrieve paginated Notification objects.|

<h2 id="tocS_package">package</h2>
<!-- backwards compatibility -->
<a id="schemapackage"></a>
<a id="schema_package"></a>
<a id="tocSpackage"></a>
<a id="tocspackage"></a>

```json
{
  "id": "10",
  "name": "libapt-pkg5.0",
  "version": "1.6.11",
  "kind": "binary",
  "normalized_version": "",
  "arch": "x86",
  "module": "",
  "cpe": "",
  "source": {
    "id": "9",
    "name": "apt",
    "version": "1.6.11",
    "kind": "source",
    "source": null
  }
}

```

Package

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|id|string|false|none|Unique ID for this Package. May be unique to the response document, not the whole system.|
|name|string|true|none|Identifier of this Package.<br><br>The uniqueness and scoping of this name depends on the packaging system.|
|version|string|true|none|Version of this Package, as reported by the packaging system.|
|kind|any|false|none|The "kind" of this Package.|
|source|[#](#schema#)|false|none|Source Package that produced the current binary Package, if known.|
|normalized_version|string|false|none|Normalized representation of the discoverd version.<br><br>The format is not specific, but is guarenteed to be forward compatible.|
|module|string|false|none|An identifier for intra-Repository grouping of packages.<br><br>Likely only relevant on rpm-based systems.|
|arch|string|false|none|Native architecture for the Package.|
|cpe|[cpe.schema.json](#schemacpe.schema.json)|false|none|CPE Name for the Package.|

#### Enumerated Values

|Property|Value|
|---|---|
|kind|BINARY|
|kind|SOURCE|

<h2 id="tocS_range">range</h2>
<!-- backwards compatibility -->
<a id="schemarange"></a>
<a id="schema_range"></a>
<a id="tocSrange"></a>
<a id="tocsrange"></a>

```json
{
  "[": "string",
  ")": "string"
}

```

Range

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|[|string|false|none|Lower bound, inclusive.|
|)|string|false|none|Upper bound, exclusive.|

<h2 id="tocS_repository">repository</h2>
<!-- backwards compatibility -->
<a id="schemarepository"></a>
<a id="schema_repository"></a>
<a id="tocSrepository"></a>
<a id="tocsrepository"></a>

```json
{
  "id": "string",
  "name": "string",
  "key": "string",
  "uri": "http://example.com",
  "cpe": null
}

```

Repository

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|id|string|true|none|Unique ID for this Repository. May be unique to the response document, not the whole system.|
|name|string|false|none|Human-relevant name for the Repository.|
|key|string|false|none|Machine-relevant name for the Repository.|
|uri|string(uri)|false|none|URI describing the Repository.|
|cpe|[cpe.schema.json](#schemacpe.schema.json)|false|none|CPE name for the Repository.|

<h2 id="tocS_update_diff">update_diff</h2>
<!-- backwards compatibility -->
<a id="schemaupdate_diff"></a>
<a id="schema_update_diff"></a>
<a id="tocSupdate_diff"></a>
<a id="tocsupdate_diff"></a>

```json
{
  "prev": null,
  "cur": null,
  "added": [],
  "removed": []
}

```

Update Difference

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|prev|[update_operation.schema.json](#schemaupdate_operation.schema.json)|false|none|The previous Update Operation.|
|cur|[update_operation.schema.json](#schemaupdate_operation.schema.json)|true|none|The current Update Operation.|
|added|[[vulnerability.schema.json](#schemavulnerability.schema.json)]|true|none|Vulnerabilities present in "cur", but not "prev".|
|removed|[[vulnerability.schema.json](#schemavulnerability.schema.json)]|true|none|Vulnerabilities present in "prev", but not "cur".|

<h2 id="tocS_update_operation">update_operation</h2>
<!-- backwards compatibility -->
<a id="schemaupdate_operation"></a>
<a id="schema_update_operation"></a>
<a id="tocSupdate_operation"></a>
<a id="tocsupdate_operation"></a>

```json
{
  "ref": "d0fad5d6-e996-4437-8fb9-5f40bbcfd7cc",
  "updater": "string",
  "fingerprint": "string",
  "date": "2019-08-24T14:15:22Z",
  "kind": "vulnerability"
}

```

Update Operation

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|ref|string(uuid)|true|none|A unique identifier for this update operation.|
|updater|string|true|none|The "updater" component that was run.|
|fingerprint|string|true|none|The stored "fingerprint" of this run.|
|date|string(date-time)|true|none|When this operation was run.|
|kind|any|true|none|The kind of data this operation updated.|

#### Enumerated Values

|Property|Value|
|---|---|
|kind|vulnerability|
|kind|enrichment|

<h2 id="tocS_update_operations">update_operations</h2>
<!-- backwards compatibility -->
<a id="schemaupdate_operations"></a>
<a id="schema_update_operations"></a>
<a id="tocSupdate_operations"></a>
<a id="tocsupdate_operations"></a>

```json
{
  "property1": [],
  "property2": []
}

```

Update Operations

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|**additionalProperties**|[[update_operation.schema.json](#schemaupdate_operation.schema.json)]|false|none|none|

<h2 id="tocS_vulnerability_core">vulnerability_core</h2>
<!-- backwards compatibility -->
<a id="schemavulnerability_core"></a>
<a id="schema_vulnerability_core"></a>
<a id="tocSvulnerability_core"></a>
<a id="tocsvulnerability_core"></a>

```json
{
  "name": "string",
  "fixed_in_version": "string",
  "severity": "string",
  "normalized_severity": null,
  "range": null,
  "arch_op": "equals",
  "package": null,
  "distribution": null,
  "repository": null
}

```

Vulnerability Core

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|name|string|true|none|Human-readable name, as presented in the vendor data.|
|fixed_in_version|string|false|none|Version string, as presented in the vendor data.|
|severity|string|false|none|Severity, as presented in the vendor data.|
|normalized_severity|[normalized_severity.schema.json](#schemanormalized_severity.schema.json)|true|none|A well defined set of severity strings guaranteed to be present.|
|range|[range.schema.json](#schemarange.schema.json)|false|none|Range of versions the vulnerability applies to.|
|arch_op|any|false|none|Flag indicating how the referenced package's "arch" member should be interpreted.|
|package|[package.schema.json](#schemapackage.schema.json)|false|none|A package description|
|distribution|[distribution.schema.json](#schemadistribution.schema.json)|false|none|A distribution description|
|repository|[repository.schema.json](#schemarepository.schema.json)|false|none|A repository description|

anyOf

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|object|false|none|none|

or

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|object|false|none|none|

or

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|object|false|none|none|

#### Enumerated Values

|Property|Value|
|---|---|
|arch_op|equals|
|arch_op|not equals|
|arch_op|pattern match|

<h2 id="tocS_vulnerability_report">vulnerability_report</h2>
<!-- backwards compatibility -->
<a id="schemavulnerability_report"></a>
<a id="schema_vulnerability_report"></a>
<a id="tocSvulnerability_report"></a>
<a id="tocsvulnerability_report"></a>

```json
{
  "manifest_hash": null,
  "packages": {},
  "distributions": {},
  "repository": {},
  "environments": {
    "property1": [],
    "property2": []
  },
  "vulnerabilities": {},
  "package_vulnerabilities": {
    "property1": [
      "string"
    ],
    "property2": [
      "string"
    ]
  },
  "enrichments": {
    "property1": [],
    "property2": []
  }
}

```

Vulnerability Report

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|manifest_hash|[digest.schema.json](#schemadigest.schema.json)|true|none|The Manifest's digest.|
|packages|object|true|none|A map of Package objects indexed by a document-local identifier.|
|» **additionalProperties**|[package.schema.json](#schemapackage.schema.json)|false|none|none|
|distributions|object|true|none|A map of Distribution objects indexed by a document-local identifier.|
|» **additionalProperties**|[distribution.schema.json](#schemadistribution.schema.json)|false|none|none|
|repository|object|false|none|A map of Repository objects indexed by a document-local identifier.|
|» **additionalProperties**|[repository.schema.json](#schemarepository.schema.json)|false|none|none|
|environments|object|true|none|A map of Environment arrays indexed by a Package's identifier.|
|» **additionalProperties**|[[environment.schema.json](#schemaenvironment.schema.json)]|false|none|none|
|vulnerabilities|object|true|none|A map of Vulnerabilities indexed by a document-local identifier.|
|» **additionalProperties**|[vulnerability.schema.json](#schemavulnerability.schema.json)|false|none|none|
|package_vulnerabilities|object|true|none|A mapping of Vulnerability identifier lists indexed by Package identifier.|
|» **additionalProperties**|[string]|false|none|none|
|enrichments|object|false|none|A mapping of extra "enrichment" data by type|
|» **additionalProperties**|array|false|none|none|

<h2 id="tocS_vulnerability">vulnerability</h2>
<!-- backwards compatibility -->
<a id="schemavulnerability"></a>
<a id="schema_vulnerability"></a>
<a id="tocSvulnerability"></a>
<a id="tocsvulnerability"></a>

```json
false

```

Vulnerability

### Properties

*None*

<h2 id="tocS_vulnerability_summaries">vulnerability_summaries</h2>
<!-- backwards compatibility -->
<a id="schemavulnerability_summaries"></a>
<a id="schema_vulnerability_summaries"></a>
<a id="tocSvulnerability_summaries"></a>
<a id="tocsvulnerability_summaries"></a>

```json
[]

```

Vulnerability Summaries

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|Vulnerability Summaries|[[vulnerability_summary.schema.json](#schemavulnerability_summary.schema.json)]|false|none|**This is an internal type, documented for completeness.**<br><br>This is an array of pseudo-Vulnerability objects used for reverse-lookup.|

<h2 id="tocS_vulnerability_summary">vulnerability_summary</h2>
<!-- backwards compatibility -->
<a id="schemavulnerability_summary"></a>
<a id="schema_vulnerability_summary"></a>
<a id="tocSvulnerability_summary"></a>
<a id="tocsvulnerability_summary"></a>

```json
false

```

Vulnerability Summary

### Properties

*None*

