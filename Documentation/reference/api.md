---
title: ClairV4 v1.1
language_tabs:
  - python: Python
  - go: Golang
  - javascript: Javascript
language_clients:
  - python: ""
  - go: ""
  - javascript: ""
toc_footers: []
includes: []
search: false
highlight_theme: darkula
headingLevel: 2

---

<!-- Generator: Widdershins v4.0.1 -->

<h1 id="clairv4">ClairV4 v1.1</h1>

> Scroll down for code samples, example requests and responses. Select a language for code samples from the tabs above or the mobile navigation menu.

ClairV4 is a set of cooperating microservices which scan, index, and match your container's content with known vulnerabilities.

Email: <a href="mailto:quay-devel@redhat.com">Clair Team</a> Web: <a href="http://github.com/quay/clair">Clair Team</a> 
License: <a href="http://www.apache.org/licenses/">Apache License 2.0</a>

<h1 id="clairv4-notifier">Notifier</h1>

## DeleteNotification

<a id="opIdDeleteNotification"></a>

> Code samples

```python
import requests
headers = {
  'Accept': 'application/json'
}

r = requests.delete('/notifier/api/v1/notification/{notification_id}', headers = headers)

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
        "Accept": []string{"application/json"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("DELETE", "/notifier/api/v1/notification/{notification_id}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

```javascript

const headers = {
  'Accept':'application/json'
};

fetch('/notifier/api/v1/notification/{notification_id}',
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

`DELETE /notifier/api/v1/notification/{notification_id}`

Issues a delete of the provided notification id and all associated notifications. After this delete clients will no longer be able to retrieve notifications.

<h3 id="deletenotification-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|notification_id|path|string|false|A notification ID returned by a callback|

> Example responses

> 400 Response

```json
{
  "code": "string",
  "message": "string"
}
```

<h3 id="deletenotification-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|OK|None|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad Request|[Error](#schemaerror)|
|405|[Method Not Allowed](https://tools.ietf.org/html/rfc7231#section-6.5.5)|Method Not Allowed|[Error](#schemaerror)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal Server Error|[Error](#schemaerror)|

<aside class="success">
This operation does not require authentication
</aside>

## Retrieve a paginated result of notifications for the provided id.

<a id="opIdGetNotification"></a>

> Code samples

```python
import requests
headers = {
  'Accept': 'application/json'
}

r = requests.get('/notifier/api/v1/notification/{notification_id}', headers = headers)

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
        "Accept": []string{"application/json"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "/notifier/api/v1/notification/{notification_id}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

```javascript

const headers = {
  'Accept':'application/json'
};

fetch('/notifier/api/v1/notification/{notification_id}',
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

`GET /notifier/api/v1/notification/{notification_id}`

By performing a GET with a notification_id as a path parameter, the client will retrieve a paginated response of notification objects.

<h3 id="retrieve-a-paginated-result-of-notifications-for-the-provided-id.-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|notification_id|path|string|false|A notification ID returned by a callback|
|page_size|query|int|false|The maximum number of notifications to deliver in a single page.|
|next|query|string|false|The next page to fetch via id. Typically this number is provided on initial response in the page.next field. The first GET request may omit this field.|

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
        "links": "http://link-to-advisory",
        "description": "In the GNU C Library (aka glibc or libc6) before 2.28, parse_reg_exp in posix/regcomp.c misparses alternatives, which allows attackers to cause a denial of service (assertion failure and application exit) or trigger an incorrect result by attempting a regular-expression match.\"",
        "normalized_severity": "Unknown",
        "package": {
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
        },
        "distribution": {
          "id": "1",
          "did": "ubuntu",
          "name": "Ubuntu",
          "version": "18.04.3 LTS (Bionic Beaver)",
          "version_code_name": "bionic",
          "version_id": "18.04",
          "arch": "",
          "cpe": "",
          "pretty_name": "Ubuntu 18.04.3 LTS"
        },
        "repository": {
          "id": "string",
          "name": "string",
          "key": "string",
          "uri": "string",
          "cpe": "string"
        }
      }
    }
  ]
}
```

<h3 id="retrieve-a-paginated-result-of-notifications-for-the-provided-id.-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|A paginated list of notifications|[PagedNotifications](#schemapagednotifications)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad Request|[Error](#schemaerror)|
|405|[Method Not Allowed](https://tools.ietf.org/html/rfc7231#section-6.5.5)|Method Not Allowed|[Error](#schemaerror)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal Server Error|[Error](#schemaerror)|

<aside class="success">
This operation does not require authentication
</aside>

<h1 id="clairv4-indexer">Indexer</h1>

## Index the contents of a Manifest

<a id="opIdIndex"></a>

> Code samples

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json'
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
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
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
      "hash": "sha256:fc84b5febd328eccaa913807716887b3eb5ed08bc22cc6933a9ebf82766725e3",
      "uri": "https://storage.example.com/blob/2f077db56abccc19f16f140f629ae98e904b4b7d563957a7fc319bd11b82ba36",
      "headers": {
        "property1": [
          "string"
        ],
        "property2": [
          "string"
        ]
      }
    }
  ]
}';
const headers = {
  'Content-Type':'application/json',
  'Accept':'application/json'
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
      "hash": "sha256:fc84b5febd328eccaa913807716887b3eb5ed08bc22cc6933a9ebf82766725e3",
      "uri": "https://storage.example.com/blob/2f077db56abccc19f16f140f629ae98e904b4b7d563957a7fc319bd11b82ba36",
      "headers": {
        "property1": [
          "string"
        ],
        "property2": [
          "string"
        ]
      }
    }
  ]
}
```

<h3 id="index-the-contents-of-a-manifest-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[Manifest](#schemamanifest)|true|none|

> Example responses

> 201 Response

```json
{
  "manifest_hash": "sha256:fc84b5febd328eccaa913807716887b3eb5ed08bc22cc6933a9ebf82766725e3",
  "state": "IndexFinished",
  "packages": {
    "10": {
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
  },
  "distributions": {
    "1": {
      "id": "1",
      "did": "ubuntu",
      "name": "Ubuntu",
      "version": "18.04.3 LTS (Bionic Beaver)",
      "version_code_name": "bionic",
      "version_id": "18.04",
      "arch": "",
      "cpe": "",
      "pretty_name": "Ubuntu 18.04.3 LTS"
    }
  },
  "environments": {
    "10": [
      {
        "package_db": "var/lib/dpkg/status",
        "introduced_in": "sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a",
        "distribution_id": "1"
      }
    ]
  },
  "success": true,
  "err": ""
}
```

<h3 id="index-the-contents-of-a-manifest-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|201|[Created](https://tools.ietf.org/html/rfc7231#section-6.3.2)|IndexReport Created|[IndexReport](#schemaindexreport)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad Request|[Error](#schemaerror)|
|405|[Method Not Allowed](https://tools.ietf.org/html/rfc7231#section-6.5.5)|Method Not Allowed|[Error](#schemaerror)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal Server Error|[Error](#schemaerror)|

<aside class="success">
This operation does not require authentication
</aside>

## Delete the IndexReport and associated information for the given Manifest hashes, if they exist.

<a id="opIdDeleteManifests"></a>

> Code samples

```python
import requests
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json'
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
        "Content-Type": []string{"application/json"},
        "Accept": []string{"application/json"},
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
  'Content-Type':'application/json',
  'Accept':'application/json'
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

<h3 id="delete-the-indexreport-and-associated-information-for-the-given-manifest-hashes,-if-they-exist.-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[BulkDelete](#schemabulkdelete)|true|none|

> Example responses

> 200 Response

```json
[
  "sha256:fc84b5febd328eccaa913807716887b3eb5ed08bc22cc6933a9ebf82766725e3"
]
```

<h3 id="delete-the-indexreport-and-associated-information-for-the-given-manifest-hashes,-if-they-exist.-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|OK|[BulkDelete](#schemabulkdelete)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad Request|[Error](#schemaerror)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal Server Error|[Error](#schemaerror)|

<aside class="success">
This operation does not require authentication
</aside>

## Delete the IndexReport and associated information for the given Manifest hash, if exists.

<a id="opIdDeleteManifest"></a>

> Code samples

```python
import requests
headers = {
  'Accept': 'application/json'
}

r = requests.delete('/indexer/api/v1/index_report/{manifest_hash}', headers = headers)

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
        "Accept": []string{"application/json"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("DELETE", "/indexer/api/v1/index_report/{manifest_hash}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

```javascript

const headers = {
  'Accept':'application/json'
};

fetch('/indexer/api/v1/index_report/{manifest_hash}',
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

`DELETE /indexer/api/v1/index_report/{manifest_hash}`

Given a Manifest's content addressable hash, any data related to it will be removed it it exists.

<h3 id="delete-the-indexreport-and-associated-information-for-the-given-manifest-hash,-if-exists.-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|manifest_hash|path|[Digest](#schemadigest)|true|A digest of a manifest that has been indexed previous to this request.|

> Example responses

> 400 Response

```json
{
  "code": "string",
  "message": "string"
}
```

<h3 id="delete-the-indexreport-and-associated-information-for-the-given-manifest-hash,-if-exists.-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|204|[No Content](https://tools.ietf.org/html/rfc7231#section-6.3.5)|OK|None|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad Request|[Error](#schemaerror)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal Server Error|[Error](#schemaerror)|

<aside class="success">
This operation does not require authentication
</aside>

## Retrieve an IndexReport for the given Manifest hash if exists.

<a id="opIdGetIndexReport"></a>

> Code samples

```python
import requests
headers = {
  'Accept': 'application/json'
}

r = requests.get('/indexer/api/v1/index_report/{manifest_hash}', headers = headers)

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
        "Accept": []string{"application/json"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "/indexer/api/v1/index_report/{manifest_hash}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

```javascript

const headers = {
  'Accept':'application/json'
};

fetch('/indexer/api/v1/index_report/{manifest_hash}',
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

`GET /indexer/api/v1/index_report/{manifest_hash}`

Given a Manifest's content addressable hash an IndexReport will be retrieved if exists.

<h3 id="retrieve-an-indexreport-for-the-given-manifest-hash-if-exists.-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|manifest_hash|path|[Digest](#schemadigest)|true|A digest of a manifest that has been indexed previous to this request.|

> Example responses

> 200 Response

```json
{
  "manifest_hash": "sha256:fc84b5febd328eccaa913807716887b3eb5ed08bc22cc6933a9ebf82766725e3",
  "state": "IndexFinished",
  "packages": {
    "10": {
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
  },
  "distributions": {
    "1": {
      "id": "1",
      "did": "ubuntu",
      "name": "Ubuntu",
      "version": "18.04.3 LTS (Bionic Beaver)",
      "version_code_name": "bionic",
      "version_id": "18.04",
      "arch": "",
      "cpe": "",
      "pretty_name": "Ubuntu 18.04.3 LTS"
    }
  },
  "environments": {
    "10": [
      {
        "package_db": "var/lib/dpkg/status",
        "introduced_in": "sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a",
        "distribution_id": "1"
      }
    ]
  },
  "success": true,
  "err": ""
}
```

<h3 id="retrieve-an-indexreport-for-the-given-manifest-hash-if-exists.-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|IndexReport retrieved|[IndexReport](#schemaindexreport)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad Request|[Error](#schemaerror)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not Found|[Error](#schemaerror)|
|405|[Method Not Allowed](https://tools.ietf.org/html/rfc7231#section-6.5.5)|Method Not Allowed|[Error](#schemaerror)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal Server Error|[Error](#schemaerror)|

<aside class="success">
This operation does not require authentication
</aside>

## Report the indexer's internal configuration and state.

<a id="opIdIndexState"></a>

> Code samples

```python
import requests
headers = {
  'Accept': 'application/json'
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
        "Accept": []string{"application/json"},
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
  'Accept':'application/json'
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
  "state": "aae368a064d7c5a433d0bf2c4f5554cc"
}
```

<h3 id="report-the-indexer's-internal-configuration-and-state.-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Indexer State|[State](#schemastate)|
|304|[Not Modified](https://tools.ietf.org/html/rfc7232#section-4.1)|Indexer State Unchanged|None|

### Response Headers

|Status|Header|Type|Format|Description|
|---|---|---|---|---|
|200|Etag|string||Entity Tag|

<aside class="success">
This operation does not require authentication
</aside>

<h1 id="clairv4-matcher">Matcher</h1>

## Retrieve a VulnerabilityReport for a given manifest's content addressable hash.

<a id="opIdGetVulnerabilityReport"></a>

> Code samples

```python
import requests
headers = {
  'Accept': 'application/json'
}

r = requests.get('/matcher/api/v1/vulnerability_report/{manifest_hash}', headers = headers)

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
        "Accept": []string{"application/json"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "/matcher/api/v1/vulnerability_report/{manifest_hash}", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

```javascript

const headers = {
  'Accept':'application/json'
};

fetch('/matcher/api/v1/vulnerability_report/{manifest_hash}',
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

`GET /matcher/api/v1/vulnerability_report/{manifest_hash}`

Given a Manifest's content addressable hash a VulnerabilityReport will be created. The Manifest **must** have been Indexed first via the Index endpoint.

<h3 id="retrieve-a-vulnerabilityreport-for-a-given-manifest's-content-addressable-hash.-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|manifest_hash|path|[Digest](#schemadigest)|true|A digest of a manifest that has been indexed previous to this request.|

> Example responses

> 201 Response

```json
{
  "manifest_hash": "sha256:fc84b5febd328eccaa913807716887b3eb5ed08bc22cc6933a9ebf82766725e3",
  "packages": {
    "10": {
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
  },
  "distributions": {
    "1": {
      "id": "1",
      "did": "ubuntu",
      "name": "Ubuntu",
      "version": "18.04.3 LTS (Bionic Beaver)",
      "version_code_name": "bionic",
      "version_id": "18.04",
      "arch": "",
      "cpe": "",
      "pretty_name": "Ubuntu 18.04.3 LTS"
    }
  },
  "environments": {
    "10": [
      {
        "package_db": "var/lib/dpkg/status",
        "introduced_in": "sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a",
        "distribution_id": "1"
      }
    ]
  },
  "vulnerabilities": {
    "356835": {
      "id": "356835",
      "updater": "",
      "name": "CVE-2009-5155",
      "description": "In the GNU C Library (aka glibc or libc6) before 2.28, parse_reg_exp in posix/regcomp.c misparses alternatives, which allows attackers to cause a denial of service (assertion failure and application exit) or trigger an incorrect result by attempting a regular-expression match.\"",
      "links": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-5155 http://people.canonical.com/~ubuntu-security/cve/2009/CVE-2009-5155.html https://sourceware.org/bugzilla/show_bug.cgi?id=11053 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=22793 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=32806 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34238 https://sourceware.org/bugzilla/show_bug.cgi?id=18986\"",
      "severity": "Low",
      "normalized_severity": "Low",
      "package": {
        "id": "0",
        "name": "glibc",
        "version": "",
        "kind": "",
        "source": null,
        "package_db": "",
        "repository_hint": ""
      },
      "dist": {
        "id": "0",
        "did": "ubuntu",
        "name": "Ubuntu",
        "version": "18.04.3 LTS (Bionic Beaver)",
        "version_code_name": "bionic",
        "version_id": "18.04",
        "arch": "",
        "cpe": "",
        "pretty_name": ""
      },
      "repo": {
        "id": "0",
        "name": "Ubuntu 18.04.3 LTS",
        "key": "",
        "uri": ""
      },
      "issued": "2019-10-12T07:20:50.52Z",
      "fixed_in_version": "2.28-0ubuntu1"
    }
  },
  "package_vulnerabilities": {
    "10": [
      "356835"
    ]
  }
}
```

<h3 id="retrieve-a-vulnerabilityreport-for-a-given-manifest's-content-addressable-hash.-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|201|[Created](https://tools.ietf.org/html/rfc7231#section-6.3.2)|VulnerabilityReport Created|[VulnerabilityReport](#schemavulnerabilityreport)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad Request|[Error](#schemaerror)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not Found|[Error](#schemaerror)|
|405|[Method Not Allowed](https://tools.ietf.org/html/rfc7231#section-6.5.5)|Method Not Allowed|[Error](#schemaerror)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal Server Error|[Error](#schemaerror)|

<aside class="success">
This operation does not require authentication
</aside>

# Schemas

<h2 id="tocS_Page">Page</h2>
<!-- backwards compatibility -->
<a id="schemapage"></a>
<a id="schema_Page"></a>
<a id="tocSpage"></a>
<a id="tocspage"></a>

```json
{
  "size": 1,
  "next": "1b4d0db2-e757-4150-bbbb-543658144205"
}

```

Page

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|size|int|false|none|The maximum number of elements in a page|
|next|string|false|none|The next id to submit to the api to continue paging|

<h2 id="tocS_PagedNotifications">PagedNotifications</h2>
<!-- backwards compatibility -->
<a id="schemapagednotifications"></a>
<a id="schema_PagedNotifications"></a>
<a id="tocSpagednotifications"></a>
<a id="tocspagednotifications"></a>

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
        "links": "http://link-to-advisory",
        "description": "In the GNU C Library (aka glibc or libc6) before 2.28, parse_reg_exp in posix/regcomp.c misparses alternatives, which allows attackers to cause a denial of service (assertion failure and application exit) or trigger an incorrect result by attempting a regular-expression match.\"",
        "normalized_severity": "Unknown",
        "package": {
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
        },
        "distribution": {
          "id": "1",
          "did": "ubuntu",
          "name": "Ubuntu",
          "version": "18.04.3 LTS (Bionic Beaver)",
          "version_code_name": "bionic",
          "version_id": "18.04",
          "arch": "",
          "cpe": "",
          "pretty_name": "Ubuntu 18.04.3 LTS"
        },
        "repository": {
          "id": "string",
          "name": "string",
          "key": "string",
          "uri": "string",
          "cpe": "string"
        }
      }
    }
  ]
}

```

PagedNotifications

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|page|object|false|none|A page object informing the client the next page to retrieve. If page.next becomes "-1" the client should stop paging.|
|notifications|[[Notification](#schemanotification)]|false|none|A list of notifications within this page|

<h2 id="tocS_Callback">Callback</h2>
<!-- backwards compatibility -->
<a id="schemacallback"></a>
<a id="schema_Callback"></a>
<a id="tocScallback"></a>
<a id="tocscallback"></a>

```json
{
  "notification_id": "269886f3-0146-4f08-9bf7-cb1138d48643",
  "callback": "http://clair-notifier/notifier/api/v1/notification/269886f3-0146-4f08-9bf7-cb1138d48643"
}

```

Callback

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|notification_id|string|false|none|the unique identifier for this set of notifications|
|callback|string|false|none|the url where notifications can be retrieved|

<h2 id="tocS_VulnSummary">VulnSummary</h2>
<!-- backwards compatibility -->
<a id="schemavulnsummary"></a>
<a id="schema_VulnSummary"></a>
<a id="tocSvulnsummary"></a>
<a id="tocsvulnsummary"></a>

```json
{
  "name": "CVE-2009-5155",
  "fixed_in_version": "v0.0.1",
  "links": "http://link-to-advisory",
  "description": "In the GNU C Library (aka glibc or libc6) before 2.28, parse_reg_exp in posix/regcomp.c misparses alternatives, which allows attackers to cause a denial of service (assertion failure and application exit) or trigger an incorrect result by attempting a regular-expression match.\"",
  "normalized_severity": "Unknown",
  "package": {
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
  },
  "distribution": {
    "id": "1",
    "did": "ubuntu",
    "name": "Ubuntu",
    "version": "18.04.3 LTS (Bionic Beaver)",
    "version_code_name": "bionic",
    "version_id": "18.04",
    "arch": "",
    "cpe": "",
    "pretty_name": "Ubuntu 18.04.3 LTS"
  },
  "repository": {
    "id": "string",
    "name": "string",
    "key": "string",
    "uri": "string",
    "cpe": "string"
  }
}

```

VulnSummary

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|name|string|false|none|the vulnerability name|
|fixed_in_version|string|false|none|The version which the vulnerability is fixed in. Empty if not fixed.|
|links|string|false|none|links to external information about vulnerability|
|description|string|false|none|the vulnerability name|
|normalized_severity|string|false|none|A well defined set of severity strings guaranteed to be present.|
|package|[Package](#schemapackage)|false|none|A package discovered by indexing a Manifest|
|distribution|[Distribution](#schemadistribution)|false|none|An indexed distribution discovered in a layer. See https://www.freedesktop.org/software/systemd/man/os-release.html for explanations and example of fields.|
|repository|[Repository](#schemarepository)|false|none|A package repository|

#### Enumerated Values

|Property|Value|
|---|---|
|normalized_severity|Unknown|
|normalized_severity|Negligible|
|normalized_severity|Low|
|normalized_severity|Medium|
|normalized_severity|High|
|normalized_severity|Critical|

<h2 id="tocS_Notification">Notification</h2>
<!-- backwards compatibility -->
<a id="schemanotification"></a>
<a id="schema_Notification"></a>
<a id="tocSnotification"></a>
<a id="tocsnotification"></a>

```json
{
  "id": "5e4b387e-88d3-4364-86fd-063447a6fad2",
  "manifest": "sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a",
  "reason": "added",
  "vulnerability": {
    "name": "CVE-2009-5155",
    "fixed_in_version": "v0.0.1",
    "links": "http://link-to-advisory",
    "description": "In the GNU C Library (aka glibc or libc6) before 2.28, parse_reg_exp in posix/regcomp.c misparses alternatives, which allows attackers to cause a denial of service (assertion failure and application exit) or trigger an incorrect result by attempting a regular-expression match.\"",
    "normalized_severity": "Unknown",
    "package": {
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
    },
    "distribution": {
      "id": "1",
      "did": "ubuntu",
      "name": "Ubuntu",
      "version": "18.04.3 LTS (Bionic Beaver)",
      "version_code_name": "bionic",
      "version_id": "18.04",
      "arch": "",
      "cpe": "",
      "pretty_name": "Ubuntu 18.04.3 LTS"
    },
    "repository": {
      "id": "string",
      "name": "string",
      "key": "string",
      "uri": "string",
      "cpe": "string"
    }
  }
}

```

Notification

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|id|string|false|none|a unique identifier for this notification|
|manifest|string|false|none|The hash of the manifest affected by the provided vulnerability.|
|reason|string|false|none|the reason for the notifcation, [added | removed]|
|vulnerability|[VulnSummary](#schemavulnsummary)|false|none|A summary of a vulnerability|

<h2 id="tocS_Environment">Environment</h2>
<!-- backwards compatibility -->
<a id="schemaenvironment"></a>
<a id="schema_Environment"></a>
<a id="tocSenvironment"></a>
<a id="tocsenvironment"></a>

```json
{
  "package_db": "var/lib/dpkg/status",
  "introduced_in": "sha256:fc84b5febd328eccaa913807716887b3eb5ed08bc22cc6933a9ebf82766725e3",
  "distribution_id": "1"
}

```

Environment

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|package_db|string|true|none|The filesystem path or unique identifier of a package database.|
|introduced_in|[Digest](#schemadigest)|true|none|A digest string with prefixed algorithm. The format is described here: https://github.com/opencontainers/image-spec/blob/master/descriptor.md#digests<br>Digests are used throughout the API to identify Layers and Manifests.|
|distribution_id|string|true|none|The distribution ID found in an associated IndexReport or VulnerabilityReport.|

<h2 id="tocS_IndexReport">IndexReport</h2>
<!-- backwards compatibility -->
<a id="schemaindexreport"></a>
<a id="schema_IndexReport"></a>
<a id="tocSindexreport"></a>
<a id="tocsindexreport"></a>

```json
{
  "manifest_hash": "sha256:fc84b5febd328eccaa913807716887b3eb5ed08bc22cc6933a9ebf82766725e3",
  "state": "IndexFinished",
  "packages": {
    "10": {
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
  },
  "distributions": {
    "1": {
      "id": "1",
      "did": "ubuntu",
      "name": "Ubuntu",
      "version": "18.04.3 LTS (Bionic Beaver)",
      "version_code_name": "bionic",
      "version_id": "18.04",
      "arch": "",
      "cpe": "",
      "pretty_name": "Ubuntu 18.04.3 LTS"
    }
  },
  "environments": {
    "10": [
      {
        "package_db": "var/lib/dpkg/status",
        "introduced_in": "sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a",
        "distribution_id": "1"
      }
    ]
  },
  "success": true,
  "err": ""
}

```

IndexReport

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|manifest_hash|[Digest](#schemadigest)|true|none|A digest string with prefixed algorithm. The format is described here: https://github.com/opencontainers/image-spec/blob/master/descriptor.md#digests<br>Digests are used throughout the API to identify Layers and Manifests.|
|state|string|true|none|The current state of the index operation|
|packages|object|true|none|A map of Package objects indexed by Package.id|
|» **additionalProperties**|[Package](#schemapackage)|false|none|A package discovered by indexing a Manifest|
|distributions|object|true|none|A map of Distribution objects keyed by their Distribution.id discovered in the manifest.|
|» **additionalProperties**|[Distribution](#schemadistribution)|false|none|An indexed distribution discovered in a layer. See https://www.freedesktop.org/software/systemd/man/os-release.html for explanations and example of fields.|
|environments|object|true|none|A map of lists containing Environment objects keyed by the associated Package.id.|
|» **additionalProperties**|[[Environment](#schemaenvironment)]|false|none|[The environment a particular package was discovered in.]|
|success|boolean|true|none|A bool indicating succcessful index|
|err|string|true|none|An error message on event of unsuccessful index|

<h2 id="tocS_VulnerabilityReport">VulnerabilityReport</h2>
<!-- backwards compatibility -->
<a id="schemavulnerabilityreport"></a>
<a id="schema_VulnerabilityReport"></a>
<a id="tocSvulnerabilityreport"></a>
<a id="tocsvulnerabilityreport"></a>

```json
{
  "manifest_hash": "sha256:fc84b5febd328eccaa913807716887b3eb5ed08bc22cc6933a9ebf82766725e3",
  "packages": {
    "10": {
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
  },
  "distributions": {
    "1": {
      "id": "1",
      "did": "ubuntu",
      "name": "Ubuntu",
      "version": "18.04.3 LTS (Bionic Beaver)",
      "version_code_name": "bionic",
      "version_id": "18.04",
      "arch": "",
      "cpe": "",
      "pretty_name": "Ubuntu 18.04.3 LTS"
    }
  },
  "environments": {
    "10": [
      {
        "package_db": "var/lib/dpkg/status",
        "introduced_in": "sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a",
        "distribution_id": "1"
      }
    ]
  },
  "vulnerabilities": {
    "356835": {
      "id": "356835",
      "updater": "",
      "name": "CVE-2009-5155",
      "description": "In the GNU C Library (aka glibc or libc6) before 2.28, parse_reg_exp in posix/regcomp.c misparses alternatives, which allows attackers to cause a denial of service (assertion failure and application exit) or trigger an incorrect result by attempting a regular-expression match.\"",
      "links": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-5155 http://people.canonical.com/~ubuntu-security/cve/2009/CVE-2009-5155.html https://sourceware.org/bugzilla/show_bug.cgi?id=11053 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=22793 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=32806 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34238 https://sourceware.org/bugzilla/show_bug.cgi?id=18986\"",
      "severity": "Low",
      "normalized_severity": "Low",
      "package": {
        "id": "0",
        "name": "glibc",
        "version": "",
        "kind": "",
        "source": null,
        "package_db": "",
        "repository_hint": ""
      },
      "dist": {
        "id": "0",
        "did": "ubuntu",
        "name": "Ubuntu",
        "version": "18.04.3 LTS (Bionic Beaver)",
        "version_code_name": "bionic",
        "version_id": "18.04",
        "arch": "",
        "cpe": "",
        "pretty_name": ""
      },
      "repo": {
        "id": "0",
        "name": "Ubuntu 18.04.3 LTS",
        "key": "",
        "uri": ""
      },
      "issued": "2019-10-12T07:20:50.52Z",
      "fixed_in_version": "2.28-0ubuntu1"
    }
  },
  "package_vulnerabilities": {
    "10": [
      "356835"
    ]
  }
}

```

VulnerabilityReport

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|manifest_hash|[Digest](#schemadigest)|true|none|A digest string with prefixed algorithm. The format is described here: https://github.com/opencontainers/image-spec/blob/master/descriptor.md#digests<br>Digests are used throughout the API to identify Layers and Manifests.|
|packages|object|true|none|A map of Package objects indexed by Package.id|
|» **additionalProperties**|[Package](#schemapackage)|false|none|A package discovered by indexing a Manifest|
|distributions|object|true|none|A map of Distribution objects indexed by Distribution.id.|
|» **additionalProperties**|[Distribution](#schemadistribution)|false|none|An indexed distribution discovered in a layer. See https://www.freedesktop.org/software/systemd/man/os-release.html for explanations and example of fields.|
|environments|object|true|none|A mapping of Environment lists indexed by Package.id|
|» **additionalProperties**|[[Environment](#schemaenvironment)]|false|none|[The environment a particular package was discovered in.]|
|vulnerabilities|object|true|none|A map of Vulnerabilities indexed by Vulnerability.id|
|» **additionalProperties**|[Vulnerability](#schemavulnerability)|false|none|A unique vulnerability indexed by Clair|
|package_vulnerabilities|object|true|none|A mapping of Vulnerability.id lists indexed by Package.id.|
|» **additionalProperties**|[string]|false|none|none|

<h2 id="tocS_Vulnerability">Vulnerability</h2>
<!-- backwards compatibility -->
<a id="schemavulnerability"></a>
<a id="schema_Vulnerability"></a>
<a id="tocSvulnerability"></a>
<a id="tocsvulnerability"></a>

```json
{
  "id": "356835",
  "updater": "",
  "name": "CVE-2009-5155",
  "description": "In the GNU C Library (aka glibc or libc6) before 2.28, parse_reg_exp in posix/regcomp.c misparses alternatives, which allows attackers to cause a denial of service (assertion failure and application exit) or trigger an incorrect result by attempting a regular-expression match.\"",
  "links": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-5155 http://people.canonical.com/~ubuntu-security/cve/2009/CVE-2009-5155.html https://sourceware.org/bugzilla/show_bug.cgi?id=11053 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=22793 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=32806 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34238 https://sourceware.org/bugzilla/show_bug.cgi?id=18986\"",
  "severity": "Low",
  "normalized_severity": "Low",
  "package": {
    "id": "0",
    "name": "glibc",
    "version": "",
    "kind": "",
    "source": null,
    "package_db": "",
    "repository_hint": ""
  },
  "dist": {
    "id": "0",
    "did": "ubuntu",
    "name": "Ubuntu",
    "version": "18.04.3 LTS (Bionic Beaver)",
    "version_code_name": "bionic",
    "version_id": "18.04",
    "arch": "",
    "cpe": "",
    "pretty_name": ""
  },
  "repo": {
    "id": "0",
    "name": "Ubuntu 18.04.3 LTS",
    "key": "",
    "uri": ""
  },
  "issued": "2019-10-12T07:20:50.52Z",
  "fixed_in_version": "2.28-0ubuntu1",
  "x-widdershins-oldRef": "#/components/examples/Vulnerability/value"
}

```

Vulnerability

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|id|string|true|none|A unique ID representing this vulnerability.|
|updater|string|true|none|A unique ID representing this vulnerability.|
|name|string|true|none|Name of this specific vulnerability.|
|description|string|true|none|A description of this specific vulnerability.|
|links|string|true|none|A space separate list of links to any external information.|
|severity|string|true|none|A severity keyword taken verbatim from the vulnerability source.|
|normalized_severity|string|true|none|A well defined set of severity strings guaranteed to be present.|
|package|[Package](#schemapackage)|false|none|A package discovered by indexing a Manifest|
|distribution|[Distribution](#schemadistribution)|false|none|An indexed distribution discovered in a layer. See https://www.freedesktop.org/software/systemd/man/os-release.html for explanations and example of fields.|
|repository|[Repository](#schemarepository)|false|none|A package repository|
|issued|string|false|none|The timestamp in which the vulnerability was issued|
|range|string|false|none|The range of package versions affected by this vulnerability.|
|fixed_in_version|string|true|none|A unique ID representing this vulnerability.|

#### Enumerated Values

|Property|Value|
|---|---|
|normalized_severity|Unknown|
|normalized_severity|Negligible|
|normalized_severity|Low|
|normalized_severity|Medium|
|normalized_severity|High|
|normalized_severity|Critical|

<h2 id="tocS_Distribution">Distribution</h2>
<!-- backwards compatibility -->
<a id="schemadistribution"></a>
<a id="schema_Distribution"></a>
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
  "arch": "",
  "cpe": "",
  "pretty_name": "Ubuntu 18.04.3 LTS",
  "x-widdershins-oldRef": "#/components/examples/Distribution/value"
}

```

Distribution

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|id|string|true|none|A unique ID representing this distribution|
|did|string|true|none|none|
|name|string|true|none|none|
|version|string|true|none|none|
|version_code_name|string|true|none|none|
|version_id|string|true|none|none|
|arch|string|true|none|none|
|cpe|string|true|none|none|
|pretty_name|string|true|none|none|

<h2 id="tocS_SourcePackage">SourcePackage</h2>
<!-- backwards compatibility -->
<a id="schemasourcepackage"></a>
<a id="schema_SourcePackage"></a>
<a id="tocSsourcepackage"></a>
<a id="tocssourcepackage"></a>

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
  },
  "x-widdershins-oldRef": "#/components/examples/Package/value"
}

```

SourcePackage

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|id|string|true|none|A unique ID representing this package|
|name|string|true|none|Name of the Package|
|version|string|true|none|Version of the Package|
|kind|string|false|none|Kind of package. Source | Binary|
|source|string|false|none|none|
|normalized_version|[Version](#schemaversion)|false|none|Version is a normalized claircore version, composed of a "kind" and an array of integers such that two versions of the same kind have the correct ordering when the integers are compared pair-wise.|
|arch|string|false|none|none|
|module|string|false|none|none|
|cpe|string|false|none|A CPE identifying the package|

<h2 id="tocS_Package">Package</h2>
<!-- backwards compatibility -->
<a id="schemapackage"></a>
<a id="schema_Package"></a>
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
  },
  "x-widdershins-oldRef": "#/components/examples/Package/value"
}

```

Package

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|id|string|true|none|A unique ID representing this package|
|name|string|true|none|Name of the Package|
|version|string|true|none|Version of the Package|
|kind|string|false|none|Kind of package. Source | Binary|
|source|[SourcePackage](#schemasourcepackage)|false|none|A source package affiliated with a Package|
|normalized_version|[Version](#schemaversion)|false|none|Version is a normalized claircore version, composed of a "kind" and an array of integers such that two versions of the same kind have the correct ordering when the integers are compared pair-wise.|
|arch|string|false|none|The package's target system architecture|
|module|string|false|none|A module further defining a namespace for a package|
|cpe|string|false|none|A CPE identifying the package|

<h2 id="tocS_Repository">Repository</h2>
<!-- backwards compatibility -->
<a id="schemarepository"></a>
<a id="schema_Repository"></a>
<a id="tocSrepository"></a>
<a id="tocsrepository"></a>

```json
{
  "id": "string",
  "name": "string",
  "key": "string",
  "uri": "string",
  "cpe": "string"
}

```

Repository

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|id|string|false|none|none|
|name|string|false|none|none|
|key|string|false|none|none|
|uri|string|false|none|none|
|cpe|string|false|none|none|

<h2 id="tocS_Version">Version</h2>
<!-- backwards compatibility -->
<a id="schemaversion"></a>
<a id="schema_Version"></a>
<a id="tocSversion"></a>
<a id="tocsversion"></a>

```json
"pep440:0.0.0.0.0.0.0.0.0"

```

Version

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|Version|string|false|none|Version is a normalized claircore version, composed of a "kind" and an array of integers such that two versions of the same kind have the correct ordering when the integers are compared pair-wise.|

<h2 id="tocS_Manifest">Manifest</h2>
<!-- backwards compatibility -->
<a id="schemamanifest"></a>
<a id="schema_Manifest"></a>
<a id="tocSmanifest"></a>
<a id="tocsmanifest"></a>

```json
{
  "hash": "sha256:fc84b5febd328eccaa913807716887b3eb5ed08bc22cc6933a9ebf82766725e3",
  "layers": [
    {
      "hash": "sha256:fc84b5febd328eccaa913807716887b3eb5ed08bc22cc6933a9ebf82766725e3",
      "uri": "https://storage.example.com/blob/2f077db56abccc19f16f140f629ae98e904b4b7d563957a7fc319bd11b82ba36",
      "headers": {
        "property1": [
          "string"
        ],
        "property2": [
          "string"
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
|hash|[Digest](#schemadigest)|true|none|A digest string with prefixed algorithm. The format is described here: https://github.com/opencontainers/image-spec/blob/master/descriptor.md#digests<br>Digests are used throughout the API to identify Layers and Manifests.|
|layers|[[Layer](#schemalayer)]|true|none|[A Layer within a Manifest and where Clair may retrieve it.]|

<h2 id="tocS_Layer">Layer</h2>
<!-- backwards compatibility -->
<a id="schemalayer"></a>
<a id="schema_Layer"></a>
<a id="tocSlayer"></a>
<a id="tocslayer"></a>

```json
{
  "hash": "sha256:fc84b5febd328eccaa913807716887b3eb5ed08bc22cc6933a9ebf82766725e3",
  "uri": "https://storage.example.com/blob/2f077db56abccc19f16f140f629ae98e904b4b7d563957a7fc319bd11b82ba36",
  "headers": {
    "property1": [
      "string"
    ],
    "property2": [
      "string"
    ]
  }
}

```

Layer

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|hash|[Digest](#schemadigest)|true|none|A digest string with prefixed algorithm. The format is described here: https://github.com/opencontainers/image-spec/blob/master/descriptor.md#digests<br>Digests are used throughout the API to identify Layers and Manifests.|
|uri|string|true|none|A URI describing where the layer may be found. Implementations MUST support http(s) schemes and MAY support additional schemes.|
|headers|object|true|none|map of arrays of header values keyed by header value. e.g. map[string][]string|
|» **additionalProperties**|[string]|false|none|none|

<h2 id="tocS_BulkDelete">BulkDelete</h2>
<!-- backwards compatibility -->
<a id="schemabulkdelete"></a>
<a id="schema_BulkDelete"></a>
<a id="tocSbulkdelete"></a>
<a id="tocsbulkdelete"></a>

```json
[
  "sha256:fc84b5febd328eccaa913807716887b3eb5ed08bc22cc6933a9ebf82766725e3"
]

```

BulkDelete

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|BulkDelete|[[Digest](#schemadigest)]|false|none|An array of Digests to be deleted.|

<h2 id="tocS_Error">Error</h2>
<!-- backwards compatibility -->
<a id="schemaerror"></a>
<a id="schema_Error"></a>
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
|message|string|false|none|a message with further detail|

<h2 id="tocS_State">State</h2>
<!-- backwards compatibility -->
<a id="schemastate"></a>
<a id="schema_State"></a>
<a id="tocSstate"></a>
<a id="tocsstate"></a>

```json
{
  "state": "aae368a064d7c5a433d0bf2c4f5554cc"
}

```

State

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|state|string|true|none|an opaque identifier|

<h2 id="tocS_Digest">Digest</h2>
<!-- backwards compatibility -->
<a id="schemadigest"></a>
<a id="schema_Digest"></a>
<a id="tocSdigest"></a>
<a id="tocsdigest"></a>

```json
"sha256:fc84b5febd328eccaa913807716887b3eb5ed08bc22cc6933a9ebf82766725e3"

```

Digest

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|Digest|string|false|none|A digest string with prefixed algorithm. The format is described here: https://github.com/opencontainers/image-spec/blob/master/descriptor.md#digests<br>Digests are used throughout the API to identify Layers and Manifests.|

