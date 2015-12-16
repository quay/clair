# General

## Fetch API Version

It returns the versions of the API and the layer processing engine.

	GET /v1/versions

* The versions are integers.
* The API version number is raised each time there is an structural change.
* The Engine version is increased when the a new layer analysis could find new
relevant data.

### Example

```
curl -s 127.0.0.1:6060/v1/versions | python -m json.tool
```

### Response

```
HTTP/1.1 200 OK
{
  "APIVersion": "1",
  "EngineVersion": "1"
}
```

## Fetch Health status

	GET /v1/health

Returns 200 if essential services are healthy (ie. database) and 503 otherwise.

This call is also available on the API port + 1, without any security, allowing
external monitoring systems to easily access it.

### Example

```
curl -s 127.0.0.1:6060/v1/health | python -m json.tool
```

```
curl -s 127.0.0.1:6061/ | python -m json.tool
```

### Success Response

```
HTTP/1.1 200 OK
{  
   "database":{  
      "IsHealthy":true
   },
   "notifier":{  
      "IsHealthy":true,
      "Details":{  
         "QueueSize":0
      }
   },
   "updater":{  
      "IsHealthy":true,
      "Details":{  
         "HealthIdentifier":"cf65a8f6-425c-4a9c-87fe-f59ddf75fc87",
         "HealthLockOwner":"1e7fce65-ee67-4ca5-b2e9-61e9f5e0d3ed",
         "LatestSuccessfulUpdate":"2015-09-30T14:47:47Z",
         "ConsecutiveLocalFailures":0
      }
   }
}
```

### Error Response

```
HTTP/1.1 503 Service unavailable
{  
   "database":{  
      "IsHealthy":false
   },
   "notifier":{  
      "IsHealthy":true,
      "Details":{  
         "QueueSize":0
      }
   },
   "updater":{  
      "IsHealthy":true,
      "Details":{  
         "HealthIdentifier":"cf65a8f6-425c-4a9c-87fe-f59ddf75fc87",
         "HealthLockOwner":"1e7fce65-ee67-4ca5-b2e9-61e9f5e0d3ed",
         "LatestSuccessfulUpdate":"2015-09-30T14:47:47Z",
         "ConsecutiveLocalFailures":0
      }
   }
}
```

# Layers

## Insert a new Layer

It processes and inserts a new Layer in the database.

	POST /v1/layers

### Parameters

|Name|Type|Description|
|------|-----|-------------|
|ID|String|Unique ID of the Layer|
|Path|String|Absolute path or HTTP link pointing to the Layer's tar file|
|ParentID|String|(Optional) Unique ID of the Layer's parent|
|ImageFormat|String|Image format of the Layer ('Docker' or 'ACI')|

If the Layer has not parent, the ParentID field should be omitted or empty.

### Example

```
curl -s -H "Content-Type: application/json" -X POST -d \
'{
	"ID": "39bb80489af75406073b5364c9c326134015140e1f7976a370a8bd446889e6f8",
	"Path": "https://layers_storage/39bb80489af75406073b5364c9c326134015140e1f7976a370a8bd446889e6f8.tar",
	"ParentID": "df2a0347c9d081fa05ecb83669dcae5830c67b0676a6d6358218e55d8a45969c"
}' \
127.0.0.1:6060/v1/layers
```

### Success Response

If the layer has been successfully processed, the version of the engine which processed it is returned.

```
HTTP/1.1 201 Created
{
    "Version": "1"
}
```

### Error Response

```
HTTP/1.1 400 Bad Request
{
    "Message": "Layer 39bb80489af75406073b5364c9c326134015140e1f7976a370a8bd446889e6f8's parent (df2a0347c9d081fa05ecb83669dcae5830c67b0676a6d6358218e55d8a45969c) is unknown."
}
```

It could also return a `415 Unsupported Media Type` response with a `Message` if the request content is not valid JSON.

## Delete a Layer

It deletes a layer from the database and any child layers that are dependent on the specified layer.

	DELETE /v1/layers/{ID}

### Parameters

|Name|Type|Description|
|------|-----|-------------|
|ID|String|Unique ID of the Layer|

### Example

```
curl -s -X DELETE 127.0.0.1:6060/v1/layers/39bb80489af75406073b5364c9c326134015140e1f7976a370a8bd446889e6f8
```

### Success Response

```
HTTP/1.1 204 No Content
```

### Error Response

```
HTTP/1.1 404 Not Found
{
    "Message": "the resource cannot be found"
}
```

//////////

## Get a Layer's operating system

It returns the operating system a given Layer.

	GET /v1/layers/{ID}/os

### Parameters

|Name|Type|Description|
|------|-----|-------------|
|ID|String|Unique ID of the Layer|

### Example

	curl -s 127.0.0.1:6060/v1/layers/39bb80489af75406073b5364c9c326134015140e1f7976a370a8bd446889e6f8/os | python -m json.tool

### Success Response

```
HTTP/1.1 200 OK
{
    "OS": "debian:8",
}
```

### Error Response
```
HTTP/1.1 404 Not Found
{
    "Message": "the resource cannot be found"
}
```

## Get a Layer's parent

It returns the parent's ID of a given Layer.
It returns an empty ID string when the layer has no parent.

	GET /v1/layers/{ID}/parent

### Parameters

|Name|Type|Description|
|------|-----|-------------|
|ID|String|Unique ID of the Layer|

### Example

	curl -s 127.0.0.1:6060/v1/layers/39bb80489af75406073b5364c9c326134015140e1f7976a370a8bd446889e6f8/parent | python -m json.tool

### Success Response

```
HTTP/1.1 200 OK
{
    "ID": "df2a0347c9d081fa05ecb83669dcae5830c67b0676a6d6358218e55d8a45969c",
}
```

### Error Response

```
HTTP/1.1 404 Not Found
{
    "Message": "the resource cannot be found"
}
```

## Get a Layer's package list

It returns the package list of a given Layer.

	GET /v1/layers/{ID}/packages

### Parameters

|Name|Type|Description|
|------|-----|-------------|
|ID|String|Unique ID of the Layer|

### Example

	curl -s 127.0.0.1:6060/v1/layers/39bb80489af75406073b5364c9c326134015140e1f7976a370a8bd446889e6f8/packages | python -m json.tool

### Success Response

```
HTTP/1.1 200 OK
{
    "Packages": [
        {
            "Name": "gcc-4.9",
            "OS": "debian:8",
            "Version": "4.9.2-10"
        },
        [...]
    ]
}
```

### Error Response
```
HTTP/1.1 404 Not Found
{
    "Message": "the resource cannot be found"
}
```

## Get a Layer's package diff

It returns the lists of packages a given Layer installs and removes.

	GET /v1/layers/{ID}/packages/diff

### Parameters

|Name|Type|Description|
|------|-----|-------------|
|ID|String|Unique ID of the Layer|

### Example

	curl -s 127.0.0.1:6060/v1/layers/39bb80489af75406073b5364c9c326134015140e1f7976a370a8bd446889e6f8/packages/diff | python -m json.tool

### Success Response

```
HTTP/1.1 200 OK
{
    "InstalledPackages": [
        {
            "Name": "gcc-4.9",
            "OS": "debian:8",
            "Version": "4.9.2-10"
        },
        [...]
    ],
    "RemovedPackages": null
}
```

### Error Response

```
HTTP/1.1 404 Not Found
{
    "Message": "the resource cannot be found"
}
```

## Get a Layer's vulnerabilities

It returns the lists of vulnerabilities which affect a given Layer.

	GET /v1/layers/{ID}/vulnerabilities(?minimumPriority=Low)

### Parameters

|Name|Type|Description|
|------|-----|-------------|
|ID|String|Unique ID of the Layer|
|minimumPriority|Priority|(Optional) The minimum priority of the returned vulnerabilities. Defaults to High|

### Example

	curl -s "127.0.0.1:6060/v1/layers/39bb80489af75406073b5364c9c326134015140e1f7976a370a8bd446889e6f8/vulnerabilities?minimumPriority=Negligible" | python -m json.tool

### Success Response

```
HTTP/1.1 200 OK
{
    "Vulnerabilities": [
        {
            "ID": "CVE-2014-2583",
            "Link": "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-2583",
            "Priority": "Low",
            "Description": "Multiple directory traversal vulnerabilities in pam_timestamp.c in the pam_timestamp module for Linux-PAM (aka pam) 1.1.8 allow local users to create aribitrary files or possibly bypass authentication via a .. (dot dot) in the (1) PAM_RUSER value to the get_ruser function or (2) PAM_TTY value to the check_tty funtion, which is used by the format_timestamp_name function.",
            "CausedByPackage": "pam"
        },
        [...]
}
```

### Error Response

```
HTTP/1.1 404 Not Found
{
    "Message": "the resource cannot be found"
}
```

## Get vulnerabilities that a layer introduces and removes

It returns the lists of vulnerabilities which are introduced and removed by the given Layer.

	GET /v1/layers/{ID}/vulnerabilities/diff(?minimumPriority=Low)

### Parameters

|Name|Type|Description|
|------|-----|-------------|
|ID|String|Unique ID of the Layer|
|minimumPriority|Priority|(Optional) The minimum priority of the returned vulnerabilities|

### Example

	curl -s "127.0.0.1:6060/v1/layers/39bb80489af75406073b5364c9c326134015140e1f7976a370a8bd446889e6f8/vulnerabilities?minimumPriority=Negligible" | python -m json.tool

### Success Response

```
HTTP/1.1 200 OK
{
    "Adds": [
        {
            "ID": "CVE-2014-2583",
            "Link": "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-2583",
            "Priority": "Low",
            "Description": "Multiple directory traversal vulnerabilities in pam_timestamp.c in the pam_timestamp module for Linux-PAM (aka pam) 1.1.8 allow local users to create aribitrary files or possibly bypass authentication via a .. (dot dot) in the (1) PAM_RUSER value to the get_ruser function or (2) PAM_TTY value to the check_tty funtion, which is used by the format_timestamp_name function.",
            "CausedByPackage": "pam"
        },
        [...]
    ],
    "Removes": null
}
```

### Error Response

```
HTTP/1.1 404 Not Found
{
    "Message": "the resource cannot be found"
}
```

## Get a Layers' vulnerabilities (Batch)

It returns the lists of vulnerabilities which affect the given Layers.

	POST /v1/batch/layers/vulnerabilities(?minimumPriority=Low)

Counterintuitively, this request is actually a POST to be able to pass a lot of parameters.

### Parameters

|Name|Type|Description|
|------|-----|-------------|
|LayersIDs|Array of strings|Unique IDs of Layers|
|minimumPriority|Priority|(Optional) The minimum priority of the returned vulnerabilities. Defaults to High|

### Example

```
curl -s -H "Content-Type: application/json" -X POST -d \
'{
		"LayersIDs": [
				"a005304e4e74c1541988d3d1abb170e338c1d45daee7151f8e82f8460634d329",
				"f1b10cd842498c23d206ee0cbeaa9de8d2ae09ff3c7af2723a9e337a6965d639"
		]
}' \
127.0.0.1:6060/v1/batch/layers/vulnerabilities
```

### Success Response

```
HTTP/1.1 200 OK
{
    "a005304e4e74c1541988d3d1abb170e338c1d45daee7151f8e82f8460634d329": {
        "Vulnerabilities": [
            {
                "ID": "CVE-2014-2583",
                "Link": "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-2583",
                "Priority": "Low",
                "Description": "Multiple directory traversal vulnerabilities in pam_timestamp.c in the pam_timestamp module for Linux-PAM (aka pam) 1.1.8 allow local users to create aribitrary files or possibly bypass authentication via a .. (dot dot) in the (1) PAM_RUSER value to the get_ruser function or (2) PAM_TTY value to the check_tty funtion, which is used by the format_timestamp_name function.",
                "CausedByPackage": "pam"
            },
            [...]
					]
		},
		[...]
}
```

### Error Response

```
HTTP/1.1 404 Not Found
{
    "Message": "the resource cannot be found"
}
```

# Vulnerabilities

## Get a vulnerability's informations

It returns all known informations about a Vulnerability and its fixes.

	GET /v1/vulnerabilities/{ID}

### Parameters

|Name|Type|Description|
|------|-----|-------------|
|ID|String|Unique ID of the Vulnerability|

### Example

	curl -s 127.0.0.1:6060/v1/vulnerabilities/CVE-2015-0235 | python -m json.tool

### Success Response

```
HTTP/1.1 200 OK
{
    "ID": "CVE-2015-0235",
    "Link": "https://security-tracker.debian.org/tracker/CVE-2015-0235",
    "Priority": "High",
    "Description": "Heap-based buffer overflow in the __nss_hostname_digits_dots function in glibc 2.2, and other 2.x versions before 2.18, allows context-dependent attackers to execute arbitrary code via vectors related to the (1) gethostbyname or (2) gethostbyname2 function, aka \"GHOST.\"",
    "AffectedPackages": [
        {
            "Name": "eglibc",
            "OS": "debian:7",
            "AllVersions": false,
            "BeforeVersion": "2.13-38+deb7u7"
        },
        {
            "Name": "glibc",
            "OS": "debian:8",
            "AllVersions": false,
            "BeforeVersion": "2.18-1"
        },
        {
            "Name": "glibc",
            "OS": "debian:9",
            "AllVersions": false,
            "BeforeVersion": "2.18-1"
        },
        {
            "Name": "glibc",
            "OS": "debian:unstable",
            "AllVersions": false,
            "BeforeVersion": "2.18-1"
        },
        {
            "Name": "eglibc",
            "OS": "debian:6",
            "AllVersions": true,
            "BeforeVersion": "",
        }
    ],
}
```

The `AffectedPackages` array represents the list of affected packages and provides the first known versions in which the Vulnerability has been fixed - each previous versions may be vulnerable. If `AllVersions` is equal to `true`, no fix exists, thus, all versions may be vulnerable.

### Error Response

```
HTTP/1.1 404 Not Found
{
    "Message":"the resource cannot be found"
}
```

## Insert a new Vulnerability

It manually inserts a new Vulnerability.

	POST /v1/vulnerabilities

### Parameters

|Name|Type|Description|
|------|-----|-------------|
|ID|String|Unique ID of the Vulnerability|
|Link|String|Link to the Vulnerability tracker|
|Priority|Priority|Priority of the Vulnerability|
|AffectedPackages|Array of Package|Affected packages (Name, OS) and fixed version (or all versions)|

If no fix exists for a package, `AllVersions` should be set to `true`.

Valid Priorities are based on [Ubuntu CVE Tracker/README](http://bazaar.launchpad.net/~ubuntu-security/ubuntu-cve-tracker/master/view/head:/README)

* **Unknown** is either a security problem that has not been ssigned to a priority yet or a priority that our system did not recognize
* **Negligible** is technically a security problem, but is only theoretical in nature, requires a very special situation, has almost no install base, or does no real damage. These tend not to get backport from upstreams, and will likely not be included in security updates unless there is an easy fix and some other issue causes an update.
* **Low** is a security problem, but is hard to exploit due to environment, requires a user-assisted attack, a small install base, or does very little damage. These tend to be included in security updates only when higher priority issues require an update, or if many low priority issues have built up.
* **Medium** is a real security problem, and is exploitable for many people. Includes network daemon denial of service attacks, cross-site scripting, and gaining user privileges. Updates should be made soon for this priority of issue.
* **High** is a real problem, exploitable for many people in a default installation. Includes serious remote denial of services, local root privilege escalations, or data loss.
* **Critical** is a world-burning problem, exploitable for nearly all people in a default installation of Ubuntu. Includes remote root privilege escalations, or massive data loss.
* **Defcon1** is a **Critical** problem which has been manually highlighted by the team. It requires an immediate attention.

### Example

```
curl -s -H "Content-Type: application/json" -X POST -d \
'{
 "ID": "CVE-2015-0235",
 "Link": "https:security-tracker.debian.org/tracker/CVE-2015-0235",
 "Priority": "High",
 "Description": "Heap-based buffer overflow in the __nss_hostname_digits_dots function in glibc 2.2, and other 2.x versions before 2.18, allows context-dependent attackers to execute arbitrary code via vectors related to the (1) gethostbyname or (2) gethostbyname2 function, aka \"GHOST.\"",
 "AffectedPackages": [
   {
       "Name": "eglibc",
       "OS": "debian:7",
       "BeforeVersion": "2.13-38+deb7u7"
   },
   {
       "Name": "glibc",
       "OS": "debian:8",
       "BeforeVersion": "2.18-1"
   },
   {
       "Name": "glibc",
       "OS": "debian:9",
       "BeforeVersion": "2.18-1"
   },
   {
       "Name": "glibc",
       "OS": "debian:unstable",
       "BeforeVersion": "2.18-1"
   },
   {
       "Name": "eglibc",
       "OS": "debian:6",
       "AllVersions": true,
       "BeforeVersion": ""
   }
 ]
}' \
127.0.0.1:6060/v1/vulnerabilities
```

### Success Response

	HTTP/1.1 201 Created

### Error Response

```
HTTP/1.1 400 Bad Request
{
	"Message":"Could not insert a vulnerability which has an invalid priority"
}
```

It could also return a `415 Unsupported Media Type` response with a `Message` if the request content is not valid JSON.

## Update a Vulnerability

It updates an existing Vulnerability.

	PUT /v1/vulnerabilities/{ID}

The Link, Priority and Description fields can be updated. FixedIn packages are added to the vulnerability. However, as a vulnerability can be fixed by only one package on a given branch (OS, Name): old FixedIn packages, which belong to the same branch as a new added one, will be removed.

### Parameters

|Name|Type|Description|
|------|-----|-------------|
|Link|String|Link to the Vulnerability tracker|
|Priority|Priority|Priority of the Vulnerability|
|FixedIn|Array of Package|Affected packages (Name, OS) and fixed version (or all versions)|

If no fix exists for a package, `AllVersions` should be set to `true`.

### Example

	curl -s -H "Content-Type: application/json" -X PUT -d '{"Priority": "Critical" }' 127.0.0.1:6060/v1/vulnerabilities/CVE-2015-0235

### Success Response

```
HTTP/1.1 204 No content
```

### Error Response

```
HTTP/1.1 404 Not Found
{
    "Message":"the resource cannot be found"
}
```

It could also return a `415 Unsupported Media Type` response with a `Message` if the request content is not valid JSON.

## Delete a Vulnerability

It deletes an existing Vulnerability.

	DEL /v1/vulnerabilities/{ID}

Be aware that it does not prevent fetcher's to re-create it. Therefore it is only useful to remove manually inserted vulnerabilities.

### Parameters

|Name|Type|Description|
|------|-----|-------------|
|ID|String|Unique ID of the Vulnerability|

### Example

	curl -s -X DEL 127.0.0.1:6060/v1/vulnerabilities/CVE-2015-0235

### Success Response

```
HTTP/1.1 204 No content
```

### Error Response

```
HTTP/1.1 404 Not Found
{
    "Message":"the resource cannot be found"
}
```

## Get layers introducing a vulnerability

It gets all the layers (their IDs) that introduce the given vulnerability.

	GET /v1/vulnerabilities/:id/introducing-layers

### Parameters

|Name|Type|Description|
|------|-----|-------------|
|ID|String|Unique ID of the Vulnerability|

### Example

	curl -s -X GET 127.0.0.1:6060/v1/vulnerabilities/CVE-2015-0235/introducing-layers

### Success Response

```
HTTP/1.1 200
{
	"IntroducingLayers":[
		"fb9cc58bde0c0a8fe53e6fdd23898e45041783f2d7869d939d7364f5777fde6f"
	]
}
```

### Error Response

```
HTTP/1.1 404 Not Found
{
    "Message":"the resource cannot be found"
}
```

## Get layers affected by a vulnerability

It returns whether the specified Layers are vulnerable to the given Vulnerability or not.

	POST /v1/vulnerabilities/{ID}/affected-layers

Counterintuitively, this request is actually a POST to be able to pass a lot of parameters.

### Parameters

|Name|Type|Description|
|------|-----|-------------|
|ID|String|Unique ID of the Vulnerability|
|LayersIDs|Array of strings|Unique IDs of Layers|

### Example

```
curl -s -H "Content-Type: application/json" -X POST -d \
'{
		"LayersIDs": [
				"a005304e4e74c1541988d3d1abb170e338c1d45daee7151f8e82f8460634d329",
				"f1b10cd842498c23d206ee0cbeaa9de8d2ae09ff3c7af2723a9e337a6965d639"
		]
}' \
127.0.0.1:6060/v1/vulnerabilities/CVE-2015-0235/affected-layers
```

### Success Response

```
HTTP/1.1 200 OK
{
   "f1b10cd842498c23d206ee0cbeaa9de8d2ae09ff3c7af2723a9e337a6965d639": {
        "Vulnerable": false
   },
   "fb9cc58bde0c0a8fe53e6fdd23898e45041783f2d7869d939d7364f5777fde6f": {
        "Vulnerable": true
   }
}
```

### Error Response

Returned when the Layer or the Vulnerability does not exist.

```
HTTP/1.1 404 Not Found
{
    "Message": "the resource cannot be found"
}
```
