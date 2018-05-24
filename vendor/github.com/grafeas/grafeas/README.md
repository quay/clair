# Grafeas: A Component Metadata API
Grafeas defines metadata API spec for computing components (e.g., VM images, container images, jar files, scripts) that can assist with aggregations over your metadata. Grafeas uses two API concepts, a **note** and an **occurrence**. This division allows 3rd party metadata providers to create and manage metadata on behalf of many customers. Additionally, the division also allows implementation of access control settings that allow fine grain access control.

## Running grafeas

To run your own Grafeas instance just follow the [instructions](docs/running_grafeas.md).

## Definition of terms
**Notes**: A note is an item or condition that can be found via an analysis or something that is used multiple times in a process. For example, a CVE could be the result of a vulnerability analysis of a Linux package. In a build process, we would store information about our builder in a note. 

A note name should take the format `/projects/<project_id>/notes/<note_id>` where the project_id would typically be different from the project where the occurrence is created and the note_id would be unique per note-project, and informative if possible. 

Access to notes should be read-only for users who have access to occurrences referencing them, and editable only by the note owner.

**Occurrences**: An occurrence can be thought of as an instantiation of a note and describes how the note was found in a specific cloud resource or project (e.g., location, specific remediation steps, etc.), or what the results of a specific note were (e.g., the container images that resulted from a build). For example, an occurrence might report that the heartbleed OpenSSL bug (a possible Note) was found in a specific package of a container image, and include information about how to remedy the heartbleed bug based on the customer’s package.

An occurrence name should take the format `/projects/<project_id>/occurrences/<occurrence_id>` where the project_id would typically be different from the project where the note is created and the occurrence_id would be unique per occurrence-project, and would often be random. 

Write access to occurrences should only be granted to users who have access to link a note to the occurrence. Any users can have read access to occurrences. 

## Kind Specific Schemas
In order to properly aggregate over metadata stored in Grafeas, each kind of information stored has a strict schema. These schemas allow normalization of data from multiple providers, giving users the ability to see meaningful insights in their components over time. Defined below are the currently supported kinds, and a brief summary of what the notes and occurrences for each of them will contain.
Specifying a kind in our notes and occurrences makes Grafeas extensible. As new metadata types need support, new kinds can be added, each with their own schema.

>TODO:Document the process for adding a new kind to the spec and generating the model, documents, and client libraries to include that kind. #38


|Kind                 |Note Summary                                                             |Occurrence Summary                               |
|---------------------|-------------------------------------------------------------------------|-------------------------------------------------|
|PACKAGE_VULNERABILITY|CVE or vulnerability description and details including severity, versions|Affected packages/versions in a specific resource|
|BUILD_DETAILS        |Builder version and signature                                            |Details of this specific build including inputs and outputs|
|IMAGE_BASIS          |Base Image for a container                                               |An image that uses the base image, and layers included on top of base image|
|PACKAGE_MANAGER      |Package Descriptions                                                     |Filesystem locations of where the package is installed in a specific resource|
|DEPLOYMENT_HISTORY   |A resource that can be deployed                                          |Details of each deployment of the resource|
|ATTESTATION          |A logical attestation "role" or "authority", used as an anchor for attestations|An attestation by an authority for a specific property and resource|



## Examples
A vulnerability scanning provider would create a note under their project with the following json for CVE-2017-14159
```json
{
  "name": "projects/security-scanner/notes/CVE-2017-14159",
  "shortDescription": "CVE-2017-14159",
  "longDescription": "NIST vectors: AV:L/AC:M/Au:N/C:N/I:N",
  "relatedUrl": [
    {
      "url": "https://security-tracker.debian.org/tracker/CVE-2017-14159",
      "label": "More Info"
    },
    {
      "url": "http://people.ubuntu.com/~ubuntu-security/cve/CVE-2017-14159",
      "label": "More Info"
    }
  ],
  "kind": "PACKAGE_VULNERABILITY",
  "createTime": "2017-09-05T21:44:52.071982Z",
  "updateTime": "2017-09-29T16:16:01.140652Z",
  "vulnerabilityType": {
    "cvssScore": 1.9,
    "severity": "LOW",
    "details": [
      {
        "cpeUri": "cpe:/o:debian:debian_linux:7",
        "severityName": "LOW",
        "fixedLocation": {
          "cpeUri": "cpe:/o:debian:debian_linux:7",
          "package": "openldap",
          "version": {
            "kind": "MAXIMUM"
          }
        },
        "minAffectedVersion": {
          "kind": "MINIMUM"
        },
        "package": "openldap",
        "description": "slapd in OpenLDAP 2.4.45 and earlier creates a PID file after dropping privileges to a non-root account, which might allow local users to kill arbitrary processes by leveraging access to this non-root account for PID file modification before a root script executes a \"kill `cat /pathname`\" command, as demonstrated by openldap-initscript."
      },
      {
        "cpeUri": "cpe:/o:debian:debian_linux:unstable",
        "severityName": "LOW",
        "fixedLocation": {
          "cpeUri": "cpe:/o:debian:debian_linux:unstable",
          "package": "openldap",
          "version": {
            "kind": "MAXIMUM"
          }
        },
        "minAffectedVersion": {
          "kind": "MINIMUM"
        },
        "package": "openldap",
        "description": "slapd in OpenLDAP 2.4.45 and earlier creates a PID file after dropping privileges to a non-root account, which might allow local users to kill arbitrary processes by leveraging access to this non-root account for PID file modification before a root script executes a \"kill `cat /pathname`\" command, as demonstrated by openldap-initscript."
      },
      {
        "cpeUri": "cpe:/o:debian:debian_linux:9",
        "severityName": "LOW",
        "fixedLocation": {
          "cpeUri": "cpe:/o:debian:debian_linux:9",
          "package": "openldap",
          "version": {
            "kind": "MAXIMUM"
          }
        },
        "minAffectedVersion": {
          "kind": "MINIMUM"
        },
        "package": "openldap",
        "description": "slapd in OpenLDAP 2.4.45 and earlier creates a PID file after dropping privileges to a non-root account, which might allow local users to kill arbitrary processes by leveraging access to this non-root account for PID file modification before a root script executes a \"kill `cat /pathname`\" command, as demonstrated by openldap-initscript."
      },
      {
        "cpeUri": "cpe:/o:debian:debian_linux:8",
        "severityName": "LOW",
        "fixedLocation": {
          "cpeUri": "cpe:/o:debian:debian_linux:8",
          "package": "openldap",
          "version": {
            "kind": "MAXIMUM"
          }
        },
        "minAffectedVersion": {
          "kind": "MINIMUM"
        },
        "package": "openldap",
        "description": "slapd in OpenLDAP 2.4.45 and earlier creates a PID file after dropping privileges to a non-root account, which might allow local users to kill arbitrary processes by leveraging access to this non-root account for PID file modification before a root script executes a \"kill `cat /pathname`\" command, as demonstrated by openldap-initscript."
      },
      {
        "cpeUri": "cpe:/o:canonical:ubuntu_linux:14.04",
        "severityName": "LOW",
        "fixedLocation": {
          "cpeUri": "cpe:/o:canonical:ubuntu_linux:14.04",
          "package": "openldap",
          "version": {
            "kind": "MAXIMUM"
          }
        },
        "minAffectedVersion": {
          "kind": "MINIMUM"
        },
        "package": "openldap",
        "description": "slapd in OpenLDAP 2.4.45 and earlier creates a PID file after dropping privileges to a non-root account, which might allow local users to kill arbitrary processes by leveraging access to this non-root account for PID file modification before a root script executes a \"kill `cat /pathname`\" command, as demonstrated by openldap-initscript."
      },
      {
        "cpeUri": "cpe:/o:canonical:ubuntu_linux:16.04",
        "severityName": "LOW",
        "fixedLocation": {
          "cpeUri": "cpe:/o:canonical:ubuntu_linux:16.04",
          "package": "openldap",
          "version": {
            "kind": "MAXIMUM"
          }
        },
        "minAffectedVersion": {
          "kind": "MINIMUM"
        },
        "package": "openldap",
        "description": "slapd in OpenLDAP 2.4.45 and earlier creates a PID file after dropping privileges to a non-root account, which might allow local users to kill arbitrary processes by leveraging access to this non-root account for PID file modification before a root script executes a \"kill `cat /pathname`\" command, as demonstrated by openldap-initscript."
      }
    ]
  }
}
```

On scanning and coming across this vulnerability, a security scanning provider would create the following in their customer’s project:

```json
{
  "name": "projects/scanning-customer/occurrences/randomId1234",
  "resourceUrl": "https://gcr.io/scanning-customer/dockerimage@sha256:hash",
  "noteName": "projects/security-scanner/notes/CVE-2017-14159",
  "kind": "PACKAGE_VULNERABILITY",
  "createTime": "2017-09-29T02:58:23.376798Z",
  "updateTime": "2017-09-29T07:35:22.141762Z",
  "vulnerabilityDetails": {
    "severity": "LOW",
    "cvssScore": 1.9,
    "packageIssue": [
      {
        "affectedLocation": {
          "cpeUri": "cpe:/o:debian:debian_linux:8",
          "package": "openldap",
          "version": {
            "name": "2.4.40+dfsg",
            "revision": "1+deb8u2"
          }
        },
        "fixedLocation": {
          "cpeUri": "cpe:/o:debian:debian_linux:8",
          "package": "openldap",
          "version": {
            "kind": "MAXIMUM"
          }
        },
        "severityName": "LOW"
      }
    ]
  }
}

```

## Resource Urls

Component resource Urls need to be unique per resource as well as immutable. This will mean that the metadata associated with a resourceUrl will always be associated with exactly one component, and what is pointed at should never change. Content addressable resource urls are preferred. In the case with resources that cannot be immutable, a timestamp should be appended.

The following table provides examples one could use as resource urls for several component types:

Component Type|Identifier                                  |Example|
--------------|--------------------------------------------|-------|
|Debian       |deb://dist(optional):arch:name:version      |deb://lucid:i386:acl:2.2.49-2|
|Docker       |https://Namespace/name@sha256:<Checksum>    |https://gcr.io/scanning-customer/dockerimage@sha256:244fd47e07d1004f0aed9c156aa09083c82bf8944eceb67c946ff7430510a77b|
|Generic file |file://sha256:<Checksum>:name               |file://sha256:244fd47e07d1004f0aed9c156aa09083c82bf8944eceb67c946ff7430510a77b:foo.jar|
|Maven        |gav://group:artifact:version                |`gav://ant:ant:1.6.5`|
|NPM          |npm://package:version                       |npm://mocha:2.4.5|
|NuGet        |nuget://module:version                      |nuget://log4net:9.0.1|
|Python       |pip://package:version                       |pip://raven:5.13.0|
|RPM          |rpm://dist(optional):arch:name:version      |rpm://el6:i386:ImageMagick:6.7.2.7-4|


## Protobuf API

The authoritative API for grafeas is the protobuf files.
[https://github.com/Grafeas/Grafeas/tree/master/v1alpha1/proto](https://github.com/Grafeas/Grafeas/tree/master/v1alpha1/proto)
We're currently working from master, and have a versioned path as well.
These paths will ideally make their way to "v1beta" and then "v1", once vetted.


## Golang API

[Documentation of `github.com/Grafeas/Grafeas/v1alpha1/proto`](https://godoc.org/github.com/Grafeas/Grafeas/v1alpha1/proto) is the golang package for the Protobuf API.

## Swagger API

To provide a JSON bridge to the Protobuf API, there is now a swagger/OpenAPI representation generated [here](https://raw.githubusercontent.com/Grafeas/Grafeas/master/v1alpha1/proto/grafeas.swagger.json).
