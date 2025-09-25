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
toc_footers: []
includes: []
search: false
highlight_theme: darkula
headingLevel: 2

---

<!-- Generator: Widdershins v4.0.1 -->

<h1 id="clair-container-analyzer">Clair Container Analyzer v1.2.0</h1>

> Scroll down for code samples, example requests and responses. Select a language for code samples from the tabs above or the mobile navigation menu.

Clair is a set of cooperating microservices which can index and match a container image's content with known vulnerabilities.

Email: <a href="mailto:quay-devel@redhat.com">Clair Team</a> Web: <a href="http://github.com/quay/clair">Clair Team</a> 
License: <a href="http://www.apache.org/licenses/">Apache License 2.0</a>

# Authentication

- HTTP Authentication, scheme: bearer Clair's authentication scheme.

<h1 id="clair-container-analyzer-indexer">indexer</h1>

## Index the contents of a Manifest

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
  "hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "layers": [
    {
      "hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856",
      "uri": "https://storage.example.com/blob/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856"
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
  "hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "layers": [
    {
      "hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856",
      "uri": "https://storage.example.com/blob/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856"
    }
  ]
}
```

<h3 id="index-the-contents-of-a-manifest-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[manifest.schema](#schemamanifest.schema)|true|none|

> Example responses

> 201 Response

```json
{
  "manifest_hash": "string",
  "state": "string",
  "err": "string",
  "success": true,
  "packages": {
    "property1": {
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
    "property2": {
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
    "property1": {
      "id": "1",
      "did": "ubuntu",
      "name": "Ubuntu",
      "version": "18.04.3 LTS (Bionic Beaver)",
      "version_code_name": "bionic",
      "version_id": "18.04",
      "pretty_name": "Ubuntu 18.04.3 LTS"
    },
    "property2": {
      "id": "1",
      "did": "ubuntu",
      "name": "Ubuntu",
      "version": "18.04.3 LTS (Bionic Beaver)",
      "version_code_name": "bionic",
      "version_id": "18.04",
      "pretty_name": "Ubuntu 18.04.3 LTS"
    }
  },
  "repository": {
    "property1": {
      "id": "string",
      "name": "string",
      "key": "string",
      "uri": "http://example.com",
      "cpe": null
    },
    "property2": {
      "id": "string",
      "name": "string",
      "key": "string",
      "uri": "http://example.com",
      "cpe": null
    }
  },
  "environments": {
    "property1": [
      {
        "value": {
          "package_db": "var/lib/dpkg/status",
          "introduced_in": "sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a",
          "distribution_id": "1"
        }
      }
    ],
    "property2": [
      {
        "value": {
          "package_db": "var/lib/dpkg/status",
          "introduced_in": "sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a",
          "distribution_id": "1"
        }
      }
    ]
  }
}
```

<h3 id="index-the-contents-of-a-manifest-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|None|
|201|[Created](https://tools.ietf.org/html/rfc7231#section-6.3.2)|IndexReport created.

Clients SHOULD not reading the body if simply submitting the manifest for later vulnerability reporting.|[index_report.schema](#schemaindex_report.schema)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad Request|[error.schema](#schemaerror.schema)|
|412|[Precondition Failed](https://tools.ietf.org/html/rfc7232#section-4.2)|none|None|
|415|[Unsupported Media Type](https://tools.ietf.org/html/rfc7231#section-6.5.13)|Unsupported Media Type|[error.schema](#schemaerror.schema)|
|default|Default|Internal Server Error|[error.schema](#schemaerror.schema)|

### Response Headers

|Status|Header|Type|Format|Description|
|---|---|---|---|---|
|200|Clair-Error|string||This is a trailer containing any errors encountered while writing the response.|
|201|Location|string||HTTP [Location header](https://httpwg.org/specs/rfc9110.html#field.location)|
|201|Link|string||Web Linking [Link header](https://httpwg.org/specs/rfc8288.html#header)|

<aside class="success">
This operation does not require authentication
</aside>

## Delete the referenced manifests.

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
  "string"
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
  "string"
]
```

<h3 id="delete-the-referenced-manifests.-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|body|body|[bulk_delete.schema](#schemabulk_delete.schema)|true|none|

> Example responses

> 200 Response

```json
[
  "string"
]
```

<h3 id="delete-the-referenced-manifests.-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|[bulk_delete.schema](#schemabulk_delete.schema)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad Request|[error.schema](#schemaerror.schema)|
|415|[Unsupported Media Type](https://tools.ietf.org/html/rfc7231#section-6.5.13)|Unsupported Media Type|[error.schema](#schemaerror.schema)|
|default|Default|Internal Server Error|[error.schema](#schemaerror.schema)|

### Response Headers

|Status|Header|Type|Format|Description|
|---|---|---|---|---|
|200|Clair-Error|string||This is a trailer containing any errors encountered while writing the response.|

<aside class="success">
This operation does not require authentication
</aside>

## Delete the referenced manifest.

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

<h3 id="delete-the-referenced-manifest.-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|digest|path|[digest.schema](#schemadigest.schema)|true|OCI-compatible digest of a referred object.|

> Example responses

> 400 Response

```json
{
  "code": "string",
  "message": "string"
}
```

<h3 id="delete-the-referenced-manifest.-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|None|
|204|[No Content](https://tools.ietf.org/html/rfc7231#section-6.3.5)|none|None|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad Request|[error.schema](#schemaerror.schema)|
|415|[Unsupported Media Type](https://tools.ietf.org/html/rfc7231#section-6.5.13)|Unsupported Media Type|[error.schema](#schemaerror.schema)|
|default|Default|Internal Server Error|[error.schema](#schemaerror.schema)|

### Response Headers

|Status|Header|Type|Format|Description|
|---|---|---|---|---|
|200|Clair-Error|string||This is a trailer containing any errors encountered while writing the response.|

<aside class="success">
This operation does not require authentication
</aside>

## Retrieve the IndexReport for the referenced manifest.

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

<h3 id="retrieve-the-indexreport-for-the-referenced-manifest.-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|digest|path|[digest.schema](#schemadigest.schema)|true|OCI-compatible digest of a referred object.|

> Example responses

> 200 Response

```json
{
  "manifest_hash": "string",
  "state": "string",
  "err": "string",
  "success": true,
  "packages": {
    "property1": {
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
    "property2": {
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
    "property1": {
      "id": "1",
      "did": "ubuntu",
      "name": "Ubuntu",
      "version": "18.04.3 LTS (Bionic Beaver)",
      "version_code_name": "bionic",
      "version_id": "18.04",
      "pretty_name": "Ubuntu 18.04.3 LTS"
    },
    "property2": {
      "id": "1",
      "did": "ubuntu",
      "name": "Ubuntu",
      "version": "18.04.3 LTS (Bionic Beaver)",
      "version_code_name": "bionic",
      "version_id": "18.04",
      "pretty_name": "Ubuntu 18.04.3 LTS"
    }
  },
  "repository": {
    "property1": {
      "id": "string",
      "name": "string",
      "key": "string",
      "uri": "http://example.com",
      "cpe": null
    },
    "property2": {
      "id": "string",
      "name": "string",
      "key": "string",
      "uri": "http://example.com",
      "cpe": null
    }
  },
  "environments": {
    "property1": [
      {
        "value": {
          "package_db": "var/lib/dpkg/status",
          "introduced_in": "sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a",
          "distribution_id": "1"
        }
      }
    ],
    "property2": [
      {
        "value": {
          "package_db": "var/lib/dpkg/status",
          "introduced_in": "sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a",
          "distribution_id": "1"
        }
      }
    ]
  }
}
```

<h3 id="retrieve-the-indexreport-for-the-referenced-manifest.-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|IndexReport retrieved|[index_report.schema](#schemaindex_report.schema)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad Request|[error.schema](#schemaerror.schema)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not Found|[error.schema](#schemaerror.schema)|
|415|[Unsupported Media Type](https://tools.ietf.org/html/rfc7231#section-6.5.13)|Unsupported Media Type|[error.schema](#schemaerror.schema)|
|default|Default|Internal Server Error|[error.schema](#schemaerror.schema)|

### Response Headers

|Status|Header|Type|Format|Description|
|---|---|---|---|---|
|200|Clair-Error|string||This is a trailer containing any errors encountered while writing the response.|

<aside class="success">
This operation does not require authentication
</aside>

## Report the indexer's internal configuration and state.

<a id="opIdIndexState"></a>

> Code samples

```python
import requests
headers = {
  'Accept': 'application/vnd.clair.indexstate.v1+json'
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
        "Accept": []string{"application/vnd.clair.indexstate.v1+json"},
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
  'Accept':'application/vnd.clair.indexstate.v1+json'
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

<h3 id="report-the-indexer's-internal-configuration-and-state.-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Indexer State|[index_state.schema](#schemaindex_state.schema)|
|304|[Not Modified](https://tools.ietf.org/html/rfc7232#section-4.1)|none|None|

### Response Headers

|Status|Header|Type|Format|Description|
|---|---|---|---|---|
|200|Etag|string||Entity Tag|

<aside class="success">
This operation does not require authentication
</aside>

<h1 id="clair-container-analyzer-matcher">matcher</h1>

## Retrieve a VulnerabilityReport for the referenced manifest.

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

<h3 id="retrieve-a-vulnerabilityreport-for-the-referenced-manifest.-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|digest|path|[digest.schema](#schemadigest.schema)|true|OCI-compatible digest of a referred object.|

> Example responses

> 201 Response

```json
{
  "manifest_hash": "string",
  "packages": {
    "property1": {
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
    "property2": {
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
    "property1": {
      "id": "1",
      "did": "ubuntu",
      "name": "Ubuntu",
      "version": "18.04.3 LTS (Bionic Beaver)",
      "version_code_name": "bionic",
      "version_id": "18.04",
      "pretty_name": "Ubuntu 18.04.3 LTS"
    },
    "property2": {
      "id": "1",
      "did": "ubuntu",
      "name": "Ubuntu",
      "version": "18.04.3 LTS (Bionic Beaver)",
      "version_code_name": "bionic",
      "version_id": "18.04",
      "pretty_name": "Ubuntu 18.04.3 LTS"
    }
  },
  "repository": {
    "property1": {
      "id": "string",
      "name": "string",
      "key": "string",
      "uri": "http://example.com",
      "cpe": null
    },
    "property2": {
      "id": "string",
      "name": "string",
      "key": "string",
      "uri": "http://example.com",
      "cpe": null
    }
  },
  "environments": {
    "property1": [
      {
        "value": {
          "package_db": "var/lib/dpkg/status",
          "introduced_in": "sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a",
          "distribution_id": "1"
        }
      }
    ],
    "property2": [
      {
        "value": {
          "package_db": "var/lib/dpkg/status",
          "introduced_in": "sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a",
          "distribution_id": "1"
        }
      }
    ]
  },
  "vulnerabilities": {
    "property1": {
      "id": "356835",
      "updater": "ubuntu",
      "name": "CVE-2009-5155",
      "description": "In the GNU C Library (aka glibc or libc6) before 2.28, parse_reg_exp in posix/regcomp.c misparses alternatives, which allows attackers to cause a denial of service (assertion failure and application exit) or trigger an incorrect result by attempting a regular-expression match.",
      "links": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-5155 http://people.canonical.com/~ubuntu-security/cve/2009/CVE-2009-5155.html https://sourceware.org/bugzilla/show_bug.cgi?id=11053 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=22793 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=32806 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34238 https://sourceware.org/bugzilla/show_bug.cgi?id=18986",
      "severity": "Low",
      "normalized_severity": "Low",
      "package": {
        "id": "0",
        "name": "glibc",
        "kind": "binary",
        "source": null
      },
      "dist": {
        "id": "0",
        "did": "ubuntu",
        "name": "Ubuntu",
        "version": "18.04.3 LTS (Bionic Beaver)",
        "version_code_name": "bionic",
        "version_id": "18.04",
        "arch": "amd64"
      },
      "repo": {
        "id": "0",
        "name": "Ubuntu 18.04.3 LTS"
      },
      "issued": "2019-10-12T07:20:50.52Z",
      "fixed_in_version": "2.28-0ubuntu1"
    },
    "property2": {
      "id": "356835",
      "updater": "ubuntu",
      "name": "CVE-2009-5155",
      "description": "In the GNU C Library (aka glibc or libc6) before 2.28, parse_reg_exp in posix/regcomp.c misparses alternatives, which allows attackers to cause a denial of service (assertion failure and application exit) or trigger an incorrect result by attempting a regular-expression match.",
      "links": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-5155 http://people.canonical.com/~ubuntu-security/cve/2009/CVE-2009-5155.html https://sourceware.org/bugzilla/show_bug.cgi?id=11053 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=22793 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=32806 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34238 https://sourceware.org/bugzilla/show_bug.cgi?id=18986",
      "severity": "Low",
      "normalized_severity": "Low",
      "package": {
        "id": "0",
        "name": "glibc",
        "kind": "binary",
        "source": null
      },
      "dist": {
        "id": "0",
        "did": "ubuntu",
        "name": "Ubuntu",
        "version": "18.04.3 LTS (Bionic Beaver)",
        "version_code_name": "bionic",
        "version_id": "18.04",
        "arch": "amd64"
      },
      "repo": {
        "id": "0",
        "name": "Ubuntu 18.04.3 LTS"
      },
      "issued": "2019-10-12T07:20:50.52Z",
      "fixed_in_version": "2.28-0ubuntu1"
    }
  },
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

<h3 id="retrieve-a-vulnerabilityreport-for-the-referenced-manifest.-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|None|
|201|[Created](https://tools.ietf.org/html/rfc7231#section-6.3.2)|Vulnerability Report Created|[vulnerability_report.schema](#schemavulnerability_report.schema)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad Request|[error.schema](#schemaerror.schema)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|Not Found|[error.schema](#schemaerror.schema)|
|415|[Unsupported Media Type](https://tools.ietf.org/html/rfc7231#section-6.5.13)|Unsupported Media Type|[error.schema](#schemaerror.schema)|
|default|Default|Internal Server Error|[error.schema](#schemaerror.schema)|

### Response Headers

|Status|Header|Type|Format|Description|
|---|---|---|---|---|
|200|Clair-Error|string||This is a trailer containing any errors encountered while writing the response.|

<aside class="success">
This operation does not require authentication
</aside>

<h1 id="clair-container-analyzer-notifier">notifier</h1>

## Delete the referenced notification set.

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

Issues a delete of the provided notification id and all associated notifications.
After this delete clients will no longer be able to retrieve notifications.

<h3 id="delete-the-referenced-notification-set.-parameters">Parameters</h3>

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

<h3 id="delete-the-referenced-notification-set.-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|None|
|204|[No Content](https://tools.ietf.org/html/rfc7231#section-6.3.5)|none|None|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad Request|[error.schema](#schemaerror.schema)|
|415|[Unsupported Media Type](https://tools.ietf.org/html/rfc7231#section-6.5.13)|Unsupported Media Type|[error.schema](#schemaerror.schema)|
|default|Default|Internal Server Error|[error.schema](#schemaerror.schema)|

### Response Headers

|Status|Header|Type|Format|Description|
|---|---|---|---|---|
|200|Clair-Error|string||This is a trailer containing any errors encountered while writing the response.|

<aside class="success">
This operation does not require authentication
</aside>

## Retrieve pages of the referenced notification set.

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

<h3 id="retrieve-pages-of-the-referenced-notification-set.-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|page_size|query|integer|false|The maximum number of notifications to deliver in a single page.|
|next|query|string|false|The next page to fetch via id. Typically this number is provided on initial response in the "page.next" field. The first request should omit this field.|
|id|path|[token](#schematoken)|true|A notification ID returned by a callback|

> Example responses

> 200 Response

```json
{
  "page": {
    "size": 0,
    "next": "-1"
  },
  "notifications": []
}
```

<h3 id="retrieve-pages-of-the-referenced-notification-set.-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|A paginated list of notifications|[notification_page.schema](#schemanotification_page.schema)|
|304|[Not Modified](https://tools.ietf.org/html/rfc7232#section-4.1)|none|None|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad Request|[error.schema](#schemaerror.schema)|
|415|[Unsupported Media Type](https://tools.ietf.org/html/rfc7231#section-6.5.13)|Unsupported Media Type|[error.schema](#schemaerror.schema)|
|default|Default|Internal Server Error|[error.schema](#schemaerror.schema)|

### Response Headers

|Status|Header|Type|Format|Description|
|---|---|---|---|---|
|200|Clair-Error|string||This is a trailer containing any errors encountered while writing the response.|

<aside class="success">
This operation does not require authentication
</aside>

<h1 id="clair-container-analyzer-internal">internal</h1>

## Retrieve the set of manifests affected by the provided vulnerabilities.

<a id="opIdAffectedManifests"></a>

> Code samples

```python
import requests
headers = {
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

const headers = {
  'Accept':'application/vnd.clair.affected_manifests.v1+json'
};

fetch('/indexer/api/v1/internal/affected_manifest',
{
  method: 'POST',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

`POST /indexer/api/v1/internal/affected_manifest`

> Example responses

> 200 Response

```json
{
  "vulnerabilities": {
    "property1": {
      "id": "356835",
      "updater": "ubuntu",
      "name": "CVE-2009-5155",
      "description": "In the GNU C Library (aka glibc or libc6) before 2.28, parse_reg_exp in posix/regcomp.c misparses alternatives, which allows attackers to cause a denial of service (assertion failure and application exit) or trigger an incorrect result by attempting a regular-expression match.",
      "links": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-5155 http://people.canonical.com/~ubuntu-security/cve/2009/CVE-2009-5155.html https://sourceware.org/bugzilla/show_bug.cgi?id=11053 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=22793 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=32806 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34238 https://sourceware.org/bugzilla/show_bug.cgi?id=18986",
      "severity": "Low",
      "normalized_severity": "Low",
      "package": {
        "id": "0",
        "name": "glibc",
        "kind": "binary",
        "source": null
      },
      "dist": {
        "id": "0",
        "did": "ubuntu",
        "name": "Ubuntu",
        "version": "18.04.3 LTS (Bionic Beaver)",
        "version_code_name": "bionic",
        "version_id": "18.04",
        "arch": "amd64"
      },
      "repo": {
        "id": "0",
        "name": "Ubuntu 18.04.3 LTS"
      },
      "issued": "2019-10-12T07:20:50.52Z",
      "fixed_in_version": "2.28-0ubuntu1"
    },
    "property2": {
      "id": "356835",
      "updater": "ubuntu",
      "name": "CVE-2009-5155",
      "description": "In the GNU C Library (aka glibc or libc6) before 2.28, parse_reg_exp in posix/regcomp.c misparses alternatives, which allows attackers to cause a denial of service (assertion failure and application exit) or trigger an incorrect result by attempting a regular-expression match.",
      "links": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-5155 http://people.canonical.com/~ubuntu-security/cve/2009/CVE-2009-5155.html https://sourceware.org/bugzilla/show_bug.cgi?id=11053 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=22793 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=32806 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34238 https://sourceware.org/bugzilla/show_bug.cgi?id=18986",
      "severity": "Low",
      "normalized_severity": "Low",
      "package": {
        "id": "0",
        "name": "glibc",
        "kind": "binary",
        "source": null
      },
      "dist": {
        "id": "0",
        "did": "ubuntu",
        "name": "Ubuntu",
        "version": "18.04.3 LTS (Bionic Beaver)",
        "version_code_name": "bionic",
        "version_id": "18.04",
        "arch": "amd64"
      },
      "repo": {
        "id": "0",
        "name": "Ubuntu 18.04.3 LTS"
      },
      "issued": "2019-10-12T07:20:50.52Z",
      "fixed_in_version": "2.28-0ubuntu1"
    }
  },
  "vulnerable_manifests": {
    "property1": [
      "string"
    ],
    "property2": [
      "string"
    ]
  }
}
```

<h3 id="retrieve-the-set-of-manifests-affected-by-the-provided-vulnerabilities.-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|[affected_manifests.schema](#schemaaffected_manifests.schema)|
|400|[Bad Request](https://tools.ietf.org/html/rfc7231#section-6.5.1)|Bad Request|[error.schema](#schemaerror.schema)|
|415|[Unsupported Media Type](https://tools.ietf.org/html/rfc7231#section-6.5.13)|Unsupported Media Type|[error.schema](#schemaerror.schema)|
|default|Default|Internal Server Error|[error.schema](#schemaerror.schema)|

### Response Headers

|Status|Header|Type|Format|Description|
|---|---|---|---|---|
|200|Clair-Error|string||This is a trailer containing any errors encountered while writing the response.|

<aside class="success">
This operation does not require authentication
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

<h2 id="tocS_manifest.schema">manifest.schema</h2>
<!-- backwards compatibility -->
<a id="schemamanifest.schema"></a>
<a id="schema_manifest.schema"></a>
<a id="tocSmanifest.schema"></a>
<a id="tocsmanifest.schema"></a>

```json
{
  "hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "layers": [
    {
      "hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856",
      "uri": "https://storage.example.com/blob/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856"
    }
  ]
}

```

Manifest

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|hash|[digest.schema.json](#schemadigest.schema.json)|true|none|#/components/schemas/digest.schema|
|layers|[[layer.schema](#schemalayer.schema)]|false|none|[Layer is a description of a container layer. It should contain enough information to fetch the layer.]|

<h2 id="tocS_index_report.schema">index_report.schema</h2>
<!-- backwards compatibility -->
<a id="schemaindex_report.schema"></a>
<a id="schema_index_report.schema"></a>
<a id="tocSindex_report.schema"></a>
<a id="tocsindex_report.schema"></a>

```json
{
  "manifest_hash": "string",
  "state": "string",
  "err": "string",
  "success": true,
  "packages": {
    "property1": {
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
    "property2": {
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
    "property1": {
      "id": "1",
      "did": "ubuntu",
      "name": "Ubuntu",
      "version": "18.04.3 LTS (Bionic Beaver)",
      "version_code_name": "bionic",
      "version_id": "18.04",
      "pretty_name": "Ubuntu 18.04.3 LTS"
    },
    "property2": {
      "id": "1",
      "did": "ubuntu",
      "name": "Ubuntu",
      "version": "18.04.3 LTS (Bionic Beaver)",
      "version_code_name": "bionic",
      "version_id": "18.04",
      "pretty_name": "Ubuntu 18.04.3 LTS"
    }
  },
  "repository": {
    "property1": {
      "id": "string",
      "name": "string",
      "key": "string",
      "uri": "http://example.com",
      "cpe": null
    },
    "property2": {
      "id": "string",
      "name": "string",
      "key": "string",
      "uri": "http://example.com",
      "cpe": null
    }
  },
  "environments": {
    "property1": [
      {
        "value": {
          "package_db": "var/lib/dpkg/status",
          "introduced_in": "sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a",
          "distribution_id": "1"
        }
      }
    ],
    "property2": [
      {
        "value": {
          "package_db": "var/lib/dpkg/status",
          "introduced_in": "sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a",
          "distribution_id": "1"
        }
      }
    ]
  }
}

```

IndexReport

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|manifest_hash|[digest.schema](#schemadigest.schema)|true|none|The Manifest's digest.|
|state|string|true|none|The current state of the index operation|
|err|string|false|none|An error message on event of unsuccessful index|
|success|boolean|true|none|A bool indicating succcessful index|
|packages|object|false|none|none|
|» **additionalProperties**|[package.schema](#schemapackage.schema)|false|none|none|
|distributions|object|false|none|none|
|» **additionalProperties**|[distribution.schema](#schemadistribution.schema)|false|none|Distribution is the accompanying system context of a Package.|
|repository|object|false|none|none|
|» **additionalProperties**|[repository.schema](#schemarepository.schema)|false|none|none|
|environments|object|false|none|none|
|» **additionalProperties**|[[environment.schema](#schemaenvironment.schema)]|false|none|[Environment describes the surrounding environment a package was discovered in.]|

<h2 id="tocS_bulk_delete.schema">bulk_delete.schema</h2>
<!-- backwards compatibility -->
<a id="schemabulk_delete.schema"></a>
<a id="schema_bulk_delete.schema"></a>
<a id="tocSbulk_delete.schema"></a>
<a id="tocsbulk_delete.schema"></a>

```json
[
  "string"
]

```

Bulk Delete

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|Bulk Delete|[[digest.schema](#schemadigest.schema)]|false|none|[A digest acts as a content identifier, enabling content addressability.]|

<h2 id="tocS_index_state.schema">index_state.schema</h2>
<!-- backwards compatibility -->
<a id="schemaindex_state.schema"></a>
<a id="schema_index_state.schema"></a>
<a id="tocSindex_state.schema"></a>
<a id="tocsindex_state.schema"></a>

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

<h2 id="tocS_affected_manifests.schema">affected_manifests.schema</h2>
<!-- backwards compatibility -->
<a id="schemaaffected_manifests.schema"></a>
<a id="schema_affected_manifests.schema"></a>
<a id="tocSaffected_manifests.schema"></a>
<a id="tocsaffected_manifests.schema"></a>

```json
{
  "vulnerabilities": {
    "property1": {
      "id": "356835",
      "updater": "ubuntu",
      "name": "CVE-2009-5155",
      "description": "In the GNU C Library (aka glibc or libc6) before 2.28, parse_reg_exp in posix/regcomp.c misparses alternatives, which allows attackers to cause a denial of service (assertion failure and application exit) or trigger an incorrect result by attempting a regular-expression match.",
      "links": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-5155 http://people.canonical.com/~ubuntu-security/cve/2009/CVE-2009-5155.html https://sourceware.org/bugzilla/show_bug.cgi?id=11053 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=22793 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=32806 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34238 https://sourceware.org/bugzilla/show_bug.cgi?id=18986",
      "severity": "Low",
      "normalized_severity": "Low",
      "package": {
        "id": "0",
        "name": "glibc",
        "kind": "binary",
        "source": null
      },
      "dist": {
        "id": "0",
        "did": "ubuntu",
        "name": "Ubuntu",
        "version": "18.04.3 LTS (Bionic Beaver)",
        "version_code_name": "bionic",
        "version_id": "18.04",
        "arch": "amd64"
      },
      "repo": {
        "id": "0",
        "name": "Ubuntu 18.04.3 LTS"
      },
      "issued": "2019-10-12T07:20:50.52Z",
      "fixed_in_version": "2.28-0ubuntu1"
    },
    "property2": {
      "id": "356835",
      "updater": "ubuntu",
      "name": "CVE-2009-5155",
      "description": "In the GNU C Library (aka glibc or libc6) before 2.28, parse_reg_exp in posix/regcomp.c misparses alternatives, which allows attackers to cause a denial of service (assertion failure and application exit) or trigger an incorrect result by attempting a regular-expression match.",
      "links": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-5155 http://people.canonical.com/~ubuntu-security/cve/2009/CVE-2009-5155.html https://sourceware.org/bugzilla/show_bug.cgi?id=11053 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=22793 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=32806 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34238 https://sourceware.org/bugzilla/show_bug.cgi?id=18986",
      "severity": "Low",
      "normalized_severity": "Low",
      "package": {
        "id": "0",
        "name": "glibc",
        "kind": "binary",
        "source": null
      },
      "dist": {
        "id": "0",
        "did": "ubuntu",
        "name": "Ubuntu",
        "version": "18.04.3 LTS (Bionic Beaver)",
        "version_code_name": "bionic",
        "version_id": "18.04",
        "arch": "amd64"
      },
      "repo": {
        "id": "0",
        "name": "Ubuntu 18.04.3 LTS"
      },
      "issued": "2019-10-12T07:20:50.52Z",
      "fixed_in_version": "2.28-0ubuntu1"
    }
  },
  "vulnerable_manifests": {
    "property1": [
      "string"
    ],
    "property2": [
      "string"
    ]
  }
}

```

Affected Manifests

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|vulnerabilities|object|false|none|none|
|» **additionalProperties**|[vulnerability.schema](#schemavulnerability.schema)|false|none|none|
|vulnerable_manifests|object|true|none|none|
|» **additionalProperties**|[string]|false|none|none|

<h2 id="tocS_vulnerability_report.schema">vulnerability_report.schema</h2>
<!-- backwards compatibility -->
<a id="schemavulnerability_report.schema"></a>
<a id="schema_vulnerability_report.schema"></a>
<a id="tocSvulnerability_report.schema"></a>
<a id="tocsvulnerability_report.schema"></a>

```json
{
  "manifest_hash": "string",
  "packages": {
    "property1": {
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
    "property2": {
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
    "property1": {
      "id": "1",
      "did": "ubuntu",
      "name": "Ubuntu",
      "version": "18.04.3 LTS (Bionic Beaver)",
      "version_code_name": "bionic",
      "version_id": "18.04",
      "pretty_name": "Ubuntu 18.04.3 LTS"
    },
    "property2": {
      "id": "1",
      "did": "ubuntu",
      "name": "Ubuntu",
      "version": "18.04.3 LTS (Bionic Beaver)",
      "version_code_name": "bionic",
      "version_id": "18.04",
      "pretty_name": "Ubuntu 18.04.3 LTS"
    }
  },
  "repository": {
    "property1": {
      "id": "string",
      "name": "string",
      "key": "string",
      "uri": "http://example.com",
      "cpe": null
    },
    "property2": {
      "id": "string",
      "name": "string",
      "key": "string",
      "uri": "http://example.com",
      "cpe": null
    }
  },
  "environments": {
    "property1": [
      {
        "value": {
          "package_db": "var/lib/dpkg/status",
          "introduced_in": "sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a",
          "distribution_id": "1"
        }
      }
    ],
    "property2": [
      {
        "value": {
          "package_db": "var/lib/dpkg/status",
          "introduced_in": "sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a",
          "distribution_id": "1"
        }
      }
    ]
  },
  "vulnerabilities": {
    "property1": {
      "id": "356835",
      "updater": "ubuntu",
      "name": "CVE-2009-5155",
      "description": "In the GNU C Library (aka glibc or libc6) before 2.28, parse_reg_exp in posix/regcomp.c misparses alternatives, which allows attackers to cause a denial of service (assertion failure and application exit) or trigger an incorrect result by attempting a regular-expression match.",
      "links": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-5155 http://people.canonical.com/~ubuntu-security/cve/2009/CVE-2009-5155.html https://sourceware.org/bugzilla/show_bug.cgi?id=11053 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=22793 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=32806 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34238 https://sourceware.org/bugzilla/show_bug.cgi?id=18986",
      "severity": "Low",
      "normalized_severity": "Low",
      "package": {
        "id": "0",
        "name": "glibc",
        "kind": "binary",
        "source": null
      },
      "dist": {
        "id": "0",
        "did": "ubuntu",
        "name": "Ubuntu",
        "version": "18.04.3 LTS (Bionic Beaver)",
        "version_code_name": "bionic",
        "version_id": "18.04",
        "arch": "amd64"
      },
      "repo": {
        "id": "0",
        "name": "Ubuntu 18.04.3 LTS"
      },
      "issued": "2019-10-12T07:20:50.52Z",
      "fixed_in_version": "2.28-0ubuntu1"
    },
    "property2": {
      "id": "356835",
      "updater": "ubuntu",
      "name": "CVE-2009-5155",
      "description": "In the GNU C Library (aka glibc or libc6) before 2.28, parse_reg_exp in posix/regcomp.c misparses alternatives, which allows attackers to cause a denial of service (assertion failure and application exit) or trigger an incorrect result by attempting a regular-expression match.",
      "links": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-5155 http://people.canonical.com/~ubuntu-security/cve/2009/CVE-2009-5155.html https://sourceware.org/bugzilla/show_bug.cgi?id=11053 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=22793 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=32806 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34238 https://sourceware.org/bugzilla/show_bug.cgi?id=18986",
      "severity": "Low",
      "normalized_severity": "Low",
      "package": {
        "id": "0",
        "name": "glibc",
        "kind": "binary",
        "source": null
      },
      "dist": {
        "id": "0",
        "did": "ubuntu",
        "name": "Ubuntu",
        "version": "18.04.3 LTS (Bionic Beaver)",
        "version_code_name": "bionic",
        "version_id": "18.04",
        "arch": "amd64"
      },
      "repo": {
        "id": "0",
        "name": "Ubuntu 18.04.3 LTS"
      },
      "issued": "2019-10-12T07:20:50.52Z",
      "fixed_in_version": "2.28-0ubuntu1"
    }
  },
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

VulnerabilityReport

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|manifest_hash|[digest.schema](#schemadigest.schema)|true|none|A digest acts as a content identifier, enabling content addressability.|
|packages|object|true|none|A map of Package objects indexed by "/id"|
|» **additionalProperties**|[package.schema](#schemapackage.schema)|false|none|none|
|distributions|object|true|none|A map of Distribution objects indexed by "/id"|
|» **additionalProperties**|[distribution.schema](#schemadistribution.schema)|false|none|Distribution is the accompanying system context of a Package.|
|repository|object|false|none|A map of Repository objects indexed by "/id"|
|» **additionalProperties**|[repository.schema](#schemarepository.schema)|false|none|none|
|environments|object|true|none|A map of Environment arrays indexed by a Package "/id"|
|» **additionalProperties**|[[environment.schema](#schemaenvironment.schema)]|false|none|[Environment describes the surrounding environment a package was discovered in.]|
|vulnerabilities|object|true|none|A map of Vulnerabilities indexed by "/id"|
|» **additionalProperties**|[vulnerability.schema](#schemavulnerability.schema)|false|none|none|
|package_vulnerabilities|object|true|none|A mapping of Vulnerability "/id" lists indexed by Package "/id"|
|» **additionalProperties**|[string]|false|none|none|
|enrichments|object|false|none|A mapping of extra "enrichment" data by type|
|» **additionalProperties**|array|false|none|none|

<h2 id="tocS_notification_page.schema">notification_page.schema</h2>
<!-- backwards compatibility -->
<a id="schemanotification_page.schema"></a>
<a id="schema_notification_page.schema"></a>
<a id="tocSnotification_page.schema"></a>
<a id="tocsnotification_page.schema"></a>

```json
{
  "page": {
    "size": 0,
    "next": "-1"
  },
  "notifications": []
}

```

Notification Page

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|page|object|true|none|An object informing the client the next page to retrieve.|
|» size|integer|true|none|none|
|» next|any|false|none|none|

oneOf

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|»» *anonymous*|string|false|none|none|

xor

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|»» *anonymous*|any|false|none|none|

continued

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|notifications|[[notification.schema](#schemanotification.schema)]|true|none|Notifications within this page.|

<h2 id="tocS_notification.schema">notification.schema</h2>
<!-- backwards compatibility -->
<a id="schemanotification.schema"></a>
<a id="schema_notification.schema"></a>
<a id="tocSnotification.schema"></a>
<a id="tocsnotification.schema"></a>

```json
{
  "id": "string",
  "manifest": null,
  "reason": "added",
  "vulnerability": {
    "name": "CVE-2009-5155",
    "description": "In the GNU C Library (aka glibc or libc6) before 2.28, parse_reg_exp in posix/regcomp.c misparses alternatives, which allows attackers to cause a denial of service (assertion failure and application exit) or trigger an incorrect result by attempting a regular-expression match.",
    "normalized_severity": "Low",
    "fixed_in_version": "v0.0.1",
    "links": "http://link-to-advisory",
    "package": {
      "id": "0",
      "name": "glibc"
    },
    "dist": {
      "id": "0",
      "did": "ubuntu",
      "name": "Ubuntu",
      "version": "18.04.3 LTS (Bionic Beaver)",
      "version_code_name": "bionic",
      "version_id": "18.04"
    },
    "repo": {
      "id": "0",
      "name": "Ubuntu 18.04.3 LTS"
    }
  }
}

```

Notification

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|id|string|true|none|Unique identifier for this notification.|
|manifest|[digest.schema.json](#schemadigest.schema.json)|true|none|#/components/schemas/digest.schema|
|reason|any|true|none|The reason for the notifcation.|
|vulnerability|[vulnerability_summary.schema](#schemavulnerability_summary.schema)|true|none|A summary of a vulnerability.|

#### Enumerated Values

|Property|Value|
|---|---|
|reason|added|
|reason|removed|

<h2 id="tocS_error.schema">error.schema</h2>
<!-- backwards compatibility -->
<a id="schemaerror.schema"></a>
<a id="schema_error.schema"></a>
<a id="tocSerror.schema"></a>
<a id="tocserror.schema"></a>

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

<h2 id="tocS_digest.schema">digest.schema</h2>
<!-- backwards compatibility -->
<a id="schemadigest.schema"></a>
<a id="schema_digest.schema"></a>
<a id="tocSdigest.schema"></a>
<a id="tocsdigest.schema"></a>

```json
"string"

```

Digest

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|Digest|string|false|none|A digest acts as a content identifier, enabling content addressability.|

oneOf

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|string|false|none|none|

xor

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|string|false|none|none|

xor

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|string|false|none|none|

<h2 id="tocS_layer.schema">layer.schema</h2>
<!-- backwards compatibility -->
<a id="schemalayer.schema"></a>
<a id="schema_layer.schema"></a>
<a id="tocSlayer.schema"></a>
<a id="tocslayer.schema"></a>

```json
{
  "hash": "string",
  "uri": "string",
  "headers": {},
  "media_type": "string"
}

```

Layer

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|hash|[digest.schema](#schemadigest.schema)|true|none|Digest of the layer blob.|
|uri|string|true|none|A URI indicating where the layer blob can be downloaded from.|
|headers|object|false|none|Any additional HTTP-style headers needed for requesting layers.|
|» ^[a-zA-Z0-9\-_]+$|[string]|false|none|none|
|media_type|string|false|none|The OCI Layer media type for this layer.|

<h2 id="tocS_package.schema">package.schema</h2>
<!-- backwards compatibility -->
<a id="schemapackage.schema"></a>
<a id="schema_package.schema"></a>
<a id="tocSpackage.schema"></a>
<a id="tocspackage.schema"></a>

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
|id|string|false|none|none|
|name|string|true|none|none|
|version|string|true|none|none|
|kind|string|false|none|none|
|source|[package.schema.json](#schemapackage.schema.json)|false|none|#/components/schemas/package.schema|
|normalized_version|string|false|none|none|
|module|string|false|none|none|
|arch|string|false|none|none|
|cpe|[cpe.schema.json](#schemacpe.schema.json)|false|none|#/components/schemas/cpe.schema|

<h2 id="tocS_distribution.schema">distribution.schema</h2>
<!-- backwards compatibility -->
<a id="schemadistribution.schema"></a>
<a id="schema_distribution.schema"></a>
<a id="tocSdistribution.schema"></a>
<a id="tocsdistribution.schema"></a>

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
|cpe|[cpe.schema.json](#schemacpe.schema.json)|false|none|#/components/schemas/cpe.schema|
|pretty_name|string|false|none|A pretty operating system name in a format suitable for presentation to the user.|

<h2 id="tocS_repository.schema">repository.schema</h2>
<!-- backwards compatibility -->
<a id="schemarepository.schema"></a>
<a id="schema_repository.schema"></a>
<a id="tocSrepository.schema"></a>
<a id="tocsrepository.schema"></a>

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
|id|string|true|none|none|
|name|string|false|none|none|
|key|string|false|none|none|
|uri|string(uri)|false|none|none|
|cpe|[cpe.schema.json](#schemacpe.schema.json)|false|none|#/components/schemas/cpe.schema|

<h2 id="tocS_environment.schema">environment.schema</h2>
<!-- backwards compatibility -->
<a id="schemaenvironment.schema"></a>
<a id="schema_environment.schema"></a>
<a id="tocSenvironment.schema"></a>
<a id="tocsenvironment.schema"></a>

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
|introduced_in|[digest.schema.json](#schemadigest.schema.json)|false|none|#/components/schemas/digest.schema|
|repository_ids|[string]|false|none|The IDs of the Repositories of the associated Package.|

<h2 id="tocS_cpe.schema">cpe.schema</h2>
<!-- backwards compatibility -->
<a id="schemacpe.schema"></a>
<a id="schema_cpe.schema"></a>
<a id="tocScpe.schema"></a>
<a id="tocscpe.schema"></a>

```json
"cpe:/a:microsoft:internet_explorer:8.0.6001:beta"

```

Common Platform Enumeration Name

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|Common Platform Enumeration Name|string|false|none|This is a CPE Name in either v2.2 "URI" form or v2.3 "Formatted String" form.|

oneOf

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|string|false|none|none|

xor

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|string|false|none|none|

<h2 id="tocS_vulnerability.schema">vulnerability.schema</h2>
<!-- backwards compatibility -->
<a id="schemavulnerability.schema"></a>
<a id="schema_vulnerability.schema"></a>
<a id="tocSvulnerability.schema"></a>
<a id="tocsvulnerability.schema"></a>

```json
{
  "id": "356835",
  "updater": "ubuntu",
  "name": "CVE-2009-5155",
  "description": "In the GNU C Library (aka glibc or libc6) before 2.28, parse_reg_exp in posix/regcomp.c misparses alternatives, which allows attackers to cause a denial of service (assertion failure and application exit) or trigger an incorrect result by attempting a regular-expression match.",
  "links": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-5155 http://people.canonical.com/~ubuntu-security/cve/2009/CVE-2009-5155.html https://sourceware.org/bugzilla/show_bug.cgi?id=11053 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=22793 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=32806 https://debbugs.gnu.org/cgi/bugreport.cgi?bug=34238 https://sourceware.org/bugzilla/show_bug.cgi?id=18986",
  "severity": "Low",
  "normalized_severity": "Low",
  "package": {
    "id": "0",
    "name": "glibc",
    "kind": "binary",
    "source": null
  },
  "dist": {
    "id": "0",
    "did": "ubuntu",
    "name": "Ubuntu",
    "version": "18.04.3 LTS (Bionic Beaver)",
    "version_code_name": "bionic",
    "version_id": "18.04",
    "arch": "amd64"
  },
  "repo": {
    "id": "0",
    "name": "Ubuntu 18.04.3 LTS"
  },
  "issued": "2019-10-12T07:20:50.52Z",
  "fixed_in_version": "2.28-0ubuntu1"
}

```

Vulnerability

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|id|string|true|none|none|
|updater|string|true|none|none|
|name|string|true|none|none|
|description|string|false|none|none|
|issued|string(date-time)|false|none|none|
|links|string|false|none|none|
|severity|string|false|none|none|
|normalized_severity|[normalized_severity.schema.json](#schemanormalized_severity.schema.json)|true|none|#/components/schemas/normalized_severity.schema|
|package|[package.schema.json](#schemapackage.schema.json)|false|none|#/components/schemas/package.schema|
|distribution|[distribution.schema.json](#schemadistribution.schema.json)|false|none|#/components/schemas/distribution.schema|
|repository|[repository.schema.json](#schemarepository.schema.json)|false|none|#/components/schemas/repository.schema|
|fixed_in_version|string|false|none|none|
|range|[range.schema.json](#schemarange.schema.json)|false|none|#/components/schemas/range.schema|
|arch_op|string|false|none|Flag indicating how the referenced package's "arch" member should be interpreted.|

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

<h2 id="tocS_normalized_severity.schema">normalized_severity.schema</h2>
<!-- backwards compatibility -->
<a id="schemanormalized_severity.schema"></a>
<a id="schema_normalized_severity.schema"></a>
<a id="tocSnormalized_severity.schema"></a>
<a id="tocsnormalized_severity.schema"></a>

```json
"Unknown"

```

Normalized Severity

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|Normalized Severity|any|false|none|none|

#### Enumerated Values

|Property|Value|
|---|---|
|Normalized Severity|Unknown|
|Normalized Severity|Negligible|
|Normalized Severity|Low|
|Normalized Severity|Medium|
|Normalized Severity|High|
|Normalized Severity|Critical|

<h2 id="tocS_range.schema">range.schema</h2>
<!-- backwards compatibility -->
<a id="schemarange.schema"></a>
<a id="schema_range.schema"></a>
<a id="tocSrange.schema"></a>
<a id="tocsrange.schema"></a>

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

anyOf

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|object|false|none|none|

or

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|*anonymous*|object|false|none|none|

<h2 id="tocS_vulnerability_summary.schema">vulnerability_summary.schema</h2>
<!-- backwards compatibility -->
<a id="schemavulnerability_summary.schema"></a>
<a id="schema_vulnerability_summary.schema"></a>
<a id="tocSvulnerability_summary.schema"></a>
<a id="tocsvulnerability_summary.schema"></a>

```json
{
  "name": "CVE-2009-5155",
  "description": "In the GNU C Library (aka glibc or libc6) before 2.28, parse_reg_exp in posix/regcomp.c misparses alternatives, which allows attackers to cause a denial of service (assertion failure and application exit) or trigger an incorrect result by attempting a regular-expression match.",
  "normalized_severity": "Low",
  "fixed_in_version": "v0.0.1",
  "links": "http://link-to-advisory",
  "package": {
    "id": "0",
    "name": "glibc"
  },
  "dist": {
    "id": "0",
    "did": "ubuntu",
    "name": "Ubuntu",
    "version": "18.04.3 LTS (Bionic Beaver)",
    "version_code_name": "bionic",
    "version_id": "18.04"
  },
  "repo": {
    "id": "0",
    "name": "Ubuntu 18.04.3 LTS"
  }
}

```

Vulnerability Summary

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|name|string|true|none|Unique identifier for this notification.|
|fixed_in_version|string|true|none|none|
|links|string|false|none|none|
|description|string|false|none|none|
|normalized_severity|[normalized_severity.schema.json](#schemanormalized_severity.schema.json)|true|none|#/components/schemas/normalized_severity.schema|
|package|[package.schema](#schemapackage.schema)|false|none|none|
|distribution|[distribution.schema](#schemadistribution.schema)|false|none|Distribution is the accompanying system context of a Package.|
|repository|[repository.schema](#schemarepository.schema)|false|none|none|

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

