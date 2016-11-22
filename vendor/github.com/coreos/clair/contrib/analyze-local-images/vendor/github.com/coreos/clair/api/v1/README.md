# Clair v1 API

- [Error Handling](#error-handling)
- [Layers](#layers)
  - [POST](#post-layers)
  - [GET](#get-layersname)
  - [DELETE](#delete-layersname)
- [Namespaces](#namespaces)
  - [GET](#get-namespaces)
- [Vulnerabilities](#vulnerabilities)
  - [List](#get-namespacesnsnamevulnerabilities)
  - [POST](#post-namespacesnamevulnerabilities)
  - [GET](#get-namespacesnsnamevulnerabilitiesvulnname)
  - [PUT](#put-namespacesnsnamevulnerabilitiesvulnname)
  - [DELETE](#delete-namespacesnsnamevulnerabilitiesvulnname)
- [Fixes](#fixes)
  - [GET](#get-namespacesnsnamevulnerabilitiesvulnnamefixes)
  - [PUT](#put-namespacesnsnamevulnerabilitiesvulnnamefixesfeaturename)
  - [DELETE](#delete-namespacesnsnamevulnerabilitiesvulnnamefixesfeaturename)
- [Notifications](#notifications)
  - [GET](#get-notificationsname)
  - [DELETE](#delete-notificationname)

## Error Handling

###### Description

Every route can optionally provide an `Error` property on the response object.
The HTTP status code of the response should indicate what type of failure occurred and how the client should reaction.

###### Client Retry Behavior

| Code | Name                  | Retry Behavior                                                                                                                                    |
|------|-----------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| 400  | Bad Request           | The body of the request invalid. The request either must be changed before being retried or depends on another request being processed before it. |
| 404  | Not Found             | The requested resource could not be found. The request must be changed before being retried.                                                      |
| 422  | Unprocessable Entity  | The request body is valid, but unsupported. This request should never be retried.                                                                 |
| 500  | Internal Server Error | The server encountered an error while processing the request. This request should be retried without change.                                      |

###### Example Response

```json
HTTP/1.1 400 Bad Request
Content-Type: application/json;charset=utf-8
Server: clair

{
  "Error": {
    "Message": "example error message"
  }
}
```

## Layers

#### POST /layers

###### Description

The POST route for the Layers resource performs the indexing of a Layer from the provided path and displays the provided Layer with an updated `IndexByVersion` property.
This request blocks for the entire duration of the downloading and indexing of the layer.

###### Example Request

```json
POST http://localhost:6060/v1/layers HTTP/1.1

{
  "Layer": {
    "Name": "523ef1d23f222195488575f52a39c729c76a8c5630c9a194139cb246fb212da6",
    "Path": "/mnt/layers/523ef1d23f222195488575f52a39c729c76a8c5630c9a194139cb246fb212da6/layer.tar",
    "ParentName": "140f9bdfeb9784cf8730e9dab5dd12fbd704151cf555ac8cae650451794e5ac2",
    "Format": "Docker"
  }
}
```

###### Example Response

```json
HTTP/1.1 201 Created
Content-Type: application/json;charset=utf-8
Server: clair

{
  "Layer": {
    "Name": "523ef1d23f222195488575f52a39c729c76a8c5630c9a194139cb246fb212da6",
    "Path": "/mnt/layers/523ef1d23f222195488575f52a39c729c76a8c5630c9a194139cb246fb212da6/layer.tar",
    "ParentName": "140f9bdfeb9784cf8730e9dab5dd12fbd704151cf555ac8cae650451794e5ac2",
    "Format": "Docker",
    "IndexedByVersion": 1
  }
}
```

#### GET /layers/`:name`

###### Description

The GET route for the Layers resource displays a Layer and optionally all of its features and vulnerabilities.

###### Query Parameters

| Name            | Type | Required | Description                                                                   |
|-----------------|------|----------|-------------------------------------------------------------------------------|
| features        | bool | optional | Displays the list of features indexed in this layer and all of its parents.   |
| vulnerabilities | bool | optional | Displays the list of vulnerabilities along with the features described above. |

###### Example Request

```
GET http://localhost:6060/v1/layers/17675ec01494d651e1ccf81dc9cf63959ebfeed4f978fddb1666b6ead008ed52?features&vulnerabilities HTTP/1.1
```

###### Example Response

```json
HTTP/1.1 200 OK
Content-Type: application/json;charset=utf-8
Server: clair

{
  "Layer": {
    "Name": "17675ec01494d651e1ccf81dc9cf63959ebfeed4f978fddb1666b6ead008ed52",
    "NamespaceName": "debian:8",
    "ParentName": "140f9bdfeb9784cf8730e9dab5dd12fbd704151cf555ac8cae650451794e5ac2",
    "IndexedByVersion": 1,
    "Features": [
      {
        "Name": "coreutils",
        "NamespaceName": "debian:8",
        "Version": "8.23-4",
        "Vulnerabilities": [
          {
            "Name": "CVE-2014-9471",
            "NamespaceName": "debian:8",
            "Description": "The parse_datetime function in GNU coreutils allows remote attackers to cause a denial of service (crash) or possibly execute arbitrary code via a crafted date string, as demonstrated by the \"--date=TZ=\"123\"345\" @1\" string to the touch or date command.",
            "Link": "https://security-tracker.debian.org/tracker/CVE-2014-9471",
            "Severity": "Low",
            "FixedBy": "9.23-5"
          }
        ]
      }
    ]
  }
}
```

#### DELETE /layers/`:name`

###### Description

The DELETE route for the Layers resource removes a Layer and all of its children from the database.

###### Example Request

```json
DELETE http://localhost:6060/v1/layers/17675ec01494d651e1ccf81dc9cf63959ebfeed4f978fddb1666b6ead008ed52 HTTP/1.1
```

###### Example Response

```json
HTTP/1.1 200 OK
Server: clair
```


## Namespaces

#### GET /namespaces

###### Description

The GET route for the Namespaces resource displays a list of namespaces currently being managed.

###### Example Request

```json
GET http://localhost:6060/v1/namespaces HTTP/1.1
```

###### Example Response

```json
HTTP/1.1 200 OK
Content-Type: application/json;charset=utf-8
Server: clair

{
  "Namespaces": [
    { "Name": "debian:8" },
    { "Name": "debian:9" }
  ]
}
```

## Vulnerabilities

#### GET /namespaces/`:nsName`/vulnerabilities

###### Description

The GET route for the Vulnerabilities resource displays the vulnerabilities data for a given namespace.

###### Query Parameters

| Name    | Type | Required | Description                                                |
|---------|------|----------|------------------------------------------------------------|
| limit   | int  | required | Limits the amount of the vunlerabilities data for a given namespace. |
| page    | int  | required | Displays the specific page of the vunlerabilities data for a given namespace. |

###### Example Request

```json
GET http://localhost:6060/v1/namespaces/debian%3A8/vulnerabilities?limit=2 HTTP/1.1
```

###### Example Response

```json
HTTP/1.1 200 OK
Content-Type: application/json;charset=utf-8
Server: clair

{
    "Vulnerabilities": [
        {
            "Name": "CVE-1999-1332",
            "NamespaceName": "debian:8",
            "Description": "gzexe in the gzip package on Red Hat Linux 5.0 and earlier allows local users to overwrite files of other users via a symlink attack on a temporary file.",
            "Link": "https://security-tracker.debian.org/tracker/CVE-1999-1332",
            "Severity": "Low"
        },
        {
            "Name": "CVE-1999-1572",
            "NamespaceName": "debian:8",
            "Description": "cpio on FreeBSD 2.1.0, Debian GNU/Linux 3.0, and possibly other operating systems, uses a 0 umask when creating files using the -O (archive) or -F options, which creates the files with mode 0666 and allows local users to read or overwrite those files.",
            "Link": "https://security-tracker.debian.org/tracker/CVE-1999-1572",
            "Severity": "Low",
            "Metadata": {
                "NVD": {
                    "CVSSv2": {
                        "Score": 2.1,
                        "Vectors": "AV:L/AC:L/Au:N/C:P/I:N"
                    }
                }
            }
        }
    ],
    "NextPage":"gAAAAABW1ABiOlm6KMDKYFE022bEy_IFJdm4ExxTNuJZMN0Eycn0Sut2tOH9bDB4EWGy5s6xwATUHiG-6JXXaU5U32sBs6_DmA=="
}
```

#### POST /namespaces/`:name`/vulnerabilities

###### Description

The POST route for the Vulnerabilities resource creates a new Vulnerability.

###### Example Request

```json
POST http://localhost:6060/v1/namespaces/debian%3A8/vulnerabilities HTTP/1.1

{
    "Vulnerability": {
        "Name": "CVE-2014-9471",
        "NamespaceName": "debian:8",
        "Link": "https://security-tracker.debian.org/tracker/CVE-2014-9471",
        "Description": "The parse_datetime function in GNU coreutils allows remote attackers to cause a denial of service (crash) or possibly execute arbitrary code via a crafted date string, as demonstrated by the \"--date=TZ=\"123\"345\" @1\" string to the touch or date command.",
        "Severity": "Low",
        "Metadata": {
            "NVD": {
                "CVSSv2": {
                    "Score": 7.5,
                    "Vectors": "AV:N/AC:L/Au:N/C:P/I:P"
                }
            }
        },
        "FixedIn": [
            {
                "Name": "coreutils",
                "NamespaceName": "debian:8",
                "Version": "8.23-1"
            }
        ]
    }
}
```

###### Example Response

```json
HTTP/1.1 201 Created
Content-Type: application/json;charset=utf-8
Server: clair

{
    "Vulnerability": {
        "Name": "CVE-2014-9471",
        "NamespaceName": "debian:8",
        "Link": "https://security-tracker.debian.org/tracker/CVE-2014-9471",
        "Description": "The parse_datetime function in GNU coreutils allows remote attackers to cause a denial of service (crash) or possibly execute arbitrary code via a crafted date string, as demonstrated by the \"--date=TZ=\"123\"345\" @1\" string to the touch or date command.",
        "Severity": "Low",
        "Metadata": {
            "NVD": {
                "CVSSv2": {
                    "Score": 7.5,
                    "Vectors": "AV:N/AC:L/Au:N/C:P/I:P"
                }
            }
        },
        "FixedIn": [
            {
                "Name": "coreutils",
                "NamespaceName": "debian:8",
                "Version": "8.23-1"
            }
        ]
    }
}
```

#### GET /namespaces/`:nsName`/vulnerabilities/`:vulnName`

###### Description

The GET route for the Vulnerabilities resource displays the current data for a given vulnerability and optionally the features that fix it.

###### Query Parameters

| Name    | Type | Required | Description                                                |
|---------|------|----------|------------------------------------------------------------|
| fixedIn | bool | optional | Displays the list of features that fix this vulnerability. |

###### Example Request

```json
GET http://localhost:6060/v1/namespaces/debian%3A8/vulnerabilities/CVE-2014-9471?fixedIn HTTP/1.1
```

###### Example Response

```json
HTTP/1.1 200 OK
Content-Type: application/json;charset=utf-8
Server: clair

{
    "Vulnerability": {
        "Name": "CVE-2014-9471",
        "NamespaceName": "debian:8",
        "Link": "https://security-tracker.debian.org/tracker/CVE-2014-9471",
        "Description": "The parse_datetime function in GNU coreutils allows remote attackers to cause a denial of service (crash) or possibly execute arbitrary code via a crafted date string, as demonstrated by the \"--date=TZ=\"123\"345\" @1\" string to the touch or date command.",
        "Severity": "Low",
        "Metadata": {
            "NVD": {
                "CVSSv2": {
                    "Score": 7.5,
                    "Vectors": "AV:N/AC:L/Au:N/C:P/I:P"
                }
            }
        },
        "FixedIn": [
            {
                "Name": "coreutils",
                "NamespaceName": "debian:8",
                "Version": "8.23-1"
            }
        ]
    }
}
```

#### PUT /namespaces/`:nsName`/vulnerabilities/`:vulnName`

###### Description

The PUT route for the Vulnerabilities resource updates a given Vulnerability.
The "FixedIn" property of the Vulnerability must be empty or missing.
Fixes should be managed by the Fixes resource.
If this vulnerability was inserted by a Fetcher, changes may be lost when the Fetcher updates.

###### Example Request

```json
PUT http://localhost:6060/v1/namespaces/debian%3A8/vulnerabilities/CVE-2014-9471

{
    "Vulnerability": {
        "Name": "CVE-2014-9471",
        "NamespaceName": "debian:8",
        "Link": "https://security-tracker.debian.org/tracker/CVE-2014-9471",
        "Description": "The parse_datetime function in GNU coreutils allows remote attackers to cause a denial of service (crash) or possibly execute arbitrary code via a crafted date string, as demonstrated by the \"--date=TZ=\"123\"345\" @1\" string to the touch or date command.",
        "Severity": "Low",
        "Metadata": {
            "NVD": {
                "CVSSv2": {
                    "Score": 7.5,
                    "Vectors": "AV:N/AC:L/Au:N/C:P/I:P"
                }
            }
        }
    }
}
```

###### Example Response

```json
HTTP/1.1 200 OK
Server: clair

{
    "Vulnerability": {
        "Name": "CVE-2014-9471",
        "NamespaceName": "debian:8",
        "Link": "https://security-tracker.debian.org/tracker/CVE-2014-9471",
        "Description": "The parse_datetime function in GNU coreutils allows remote attackers to cause a denial of service (crash) or possibly execute arbitrary code via a crafted date string, as demonstrated by the \"--date=TZ=\"123\"345\" @1\" string to the touch or date command.",
        "Severity": "Low",
        "Metadata": {
            "NVD": {
                "CVSSv2": {
                    "Score": 7.5,
                    "Vectors": "AV:N/AC:L/Au:N/C:P/I:P"
                }
            }
        }
    }
}
```


#### DELETE /namespaces/`:nsName`/vulnerabilities/`:vulnName`

###### Description

The DELETE route for the Vulnerabilities resource deletes a given Vulnerability.
If this vulnerability was inserted by a Fetcher, it may be re-inserted when the Fetcher updates.

###### Example Request

```json
GET http://localhost:6060/v1/namespaces/debian%3A8/vulnerabilities/CVE-2014-9471 HTTP/1.1
```

###### Example Response

```json
HTTP/1.1 200 OK
Server: clair
```

## Fixes

#### GET /namespaces/`:nsName`/vulnerabilities/`:vulnName`/fixes

###### Description

The GET route for the Fixes resource displays the list of Features that fix the given Vulnerability.

###### Example Request

```json
GET http://localhost:6060/v1/namespaces/debian%3A8/vulnerabilities/CVE-2014-9471/fixes HTTP/1.1
```

###### Example Response

```json
HTTP/1.1 200 OK
Content-Type: application/json;charset=utf-8
Server: clair

{
  "Features": [
    {
      "Name": "coreutils",
      "NamespaceName": "debian:8",
      "Version": "8.23-1"
    }
  ]
}
```

#### PUT /namespaces/`:nsName`/vulnerabilities/`:vulnName`/fixes/`:featureName`

###### Description

The PUT route for the Fixes resource updates a Feature that is the fix for a given Vulnerability.

###### Example Request

```json
PUT http://localhost:6060/v1/namespaces/debian%3A8/vulnerabilities/CVE-2014-9471/fixes/coreutils HTTP/1.1

{
  "Feature": {
    "Name": "coreutils",
    "NamespaceName": "debian:8",
    "Version": "4.24-9"
  }
}
```

###### Example Response

```json
HTTP/1.1 200 OK
Server: clair

{
  "Feature": {
    "Name": "coreutils",
    "NamespaceName": "debian:8",
    "Version": "4.24-9"
  }
}
```

#### DELETE /namespaces/`:nsName`/vulnerabilities/`:vulnName`/fixes/`:featureName`

###### Description

The DELETE route for the Fixes resource removes a Feature as fix for the given Vulnerability.

###### Example Request

```json
DELETE http://localhost:6060/v1/namespaces/debian%3A8/vulnerabilities/CVE-2014-9471/fixes/coreutils
```

###### Example Response

```json
HTTP/1.1 200 OK
Server: clair
```

## Notifications

#### GET /notifications/`:name`

###### Description

The GET route for the Notifications resource displays a notification that a Vulnerability has been updated.
This route supports simultaneous pagination for both the `Old` and `New` Vulnerabilities' `LayersIntroducingVulnerability` property which can be extremely long.

###### Query Parameters

| Name  | Type   | Required | Description                                                                                                   |
|-------|--------|----------|---------------------------------------------------------------------------------------------------------------|
| page  | string | optional | Displays the specific page of the "LayersIntroducingVulnerability" property on New and Old vulnerabilities.   |
| limit | int    | optional | Limits the amount of results in the "LayersIntroducingVulnerability" property on New and Old vulnerabilities. |

###### Example Request

```json
GET http://localhost:6060/v1/notifications/ec45ec87-bfc8-4129-a1c3-d2b82622175a?limit=2 HTTP/1.1
```

###### Example Response

```json
HTTP/1.1 200 OK
Content-Type: application/json;charset=utf-8
Server: clair

{
  "Notification": {
    "Name": "ec45ec87-bfc8-4129-a1c3-d2b82622175a",
    "Created": "1456247389",
    "Notified": "1456246708",
    "Limit": 2,
    "Page": "gAAAAABWzJaC2JCH6Apr_R1f2EkjGdibnrKOobTcYXBWl6t0Cw6Q04ENGIymB6XlZ3Zi0bYt2c-2cXe43fvsJ7ECZhZz4P8C8F9efr_SR0HPiejzQTuG0qAzeO8klogFfFjSz2peBvgP",
    "NextPage": "gAAAAABWzJaCTyr6QXP2aYsCwEZfWIkU2GkNplSMlTOhLJfiR3LorBv8QYgEIgyOvZRmHQEzJKvkI6TP2PkRczBkcD17GE89btaaKMqEX14yHDgyfQvdasW1tj3-5bBRt0esKi9ym5En",
    "New": {
      "Vulnerability": {
        "Name": "CVE-TEST",
        "NamespaceName": "debian:8",
        "Description": "New CVE",
        "Severity": "Low",
        "FixedIn": [
          {
            "Name": "grep",
            "NamespaceName": "debian:8",
            "Version": "2.25"
          }
        ]
      },
      "LayersIntroducingVulnerability": [
        "3b59c795b34670618fbcace4dac7a27c5ecec156812c9e2c90d3f4be1916b12d.9673fdf7-b81a-4b3e-acf8-e551ef155449",
        "523ef1d23f222195488575f52a39c729c76a8c5630c9a194139cb246fb212da6"
      ]
    },
    "Old": {
      "Vulnerability": {
        "Name": "CVE-TEST",
        "NamespaceName": "debian:8",
        "Description": "New CVE",
        "Severity": "Low",
        "FixedIn": []
      },
      "LayersIntroducingVulnerability": [
        "3b59c795b34670618fbcace4dac7a27c5ecec156812c9e2c90d3f4be1916b12d.9673fdf7-b81a-4b3e-acf8-e551ef155449",
        "523ef1d23f222195488575f52a39c729c76a8c5630c9a194139cb246fb212da6"
      ]
    }
  }
}
```

#### DELETE /notifications/`:name`

###### Description

The delete route for the Notifications resource marks a Notification as read.
If a notification is not marked as read, Clair will continue to notify the provided endpoints.
The time at which this Notification was marked as read can be seen in the `Notified` property of the response GET route for Notification.

###### Example Request

```json
DELETE http://localhost:6060/v1/notification/ec45ec87-bfc8-4129-a1c3-d2b82622175a HTTP/1.1
```

###### Example Response

```json
HTTP/1.1 200 OK
Server: clair
```
