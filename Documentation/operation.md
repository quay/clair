# Operation

## Releases

All of the source code needed to build clair is packaged as an archive and
attached to the release. Releases are tracked at the [github releases].

[github releases]: https://github.com/quay/clair/releases

## Official Containers

Clair is officially packaged and released as a container at
[quay.io/projectquay/clair]. The `latest` tag tracks the git development branch,
and version tags are built from the corresponding release.

[quay.io/projectquay/clair]: https://quay.io/repository/projectquay/clair

## Architecture

Clair is structured so that it can be easily scaled with demand. It can be
broken up into up to 3 microservices as needed ([Indexer], [Matcher], and
[Notifier]) or run as a single monolith. Each process talks to separate tables
in the database and is responsible for disparate API endpoints.

[Indexer]: #indexer
[Matcher]: #matcher
[Notifier]: #notifier

### Indexer

Responsible for ...

### Matcher

Responsible for ...

### Notifier

Responsible for ...

## Ingress

One recommended configuration is to use some sort of service ingress to route
API endpoints to the component responsible for servicing it.

## Authentication

Previous versions of Clair used [jwtproxy] to gate authentication. For ease of
building and deployment, v4 handles authentication itself.

Authentication is configured by specifying configuration objects underneath the
`auth` key of the configuration. Multiple authentication configurations may be
present, but they will be used preferentially in the order laid out below.

[jwtproxy]: https://github.com/quay/jwtproxy

### Quay Integration

Quay implements a keyserver protocol that allows for publishing and rotating
keys in an automated fashion. Any process that has successfully enrolled in the
keyserver that Clair is configured to talk to should be able to sign requests to
Clair.

#### Configuration

The `auth` stanza of the configuration file requires one parameter, `api`, which
is the API endpoint of keyserver protocol.

```yaml
auth:
  keyserver:
    api: 'https://quay.example.com/keys/'
```

##### Intraservice

When Clair instances are configured with keyserver authentication and run in any
other mode besides "combo", an additional `intraservice` key is
required. This key is used for signing and verifying requests within the
Clair service cluster.

```yaml
auth:
  keyserver:
    api: 'https://quay.example.com/keys/'
    intraservice: >-
      MDQ4ODBlNDAtNDc0ZC00MWUxLThhMzAtOTk0MzEwMGQwYTMxCg==
```

### PSK

Clair implements JWT-based authentication using a pre-shared key.

#### Configuration

The `auth` stanza of the configuration file requires two parameters: `iss`, which
is the issuer to validate on all incoming requests; and `key`, which is a base64
encoded symmetric key for validating the requests.

```yaml
auth:
  psk:
    key: >-
      MDQ4ODBlNDAtNDc0ZC00MWUxLThhMzAtOTk0MzEwMGQwYTMxCg==
    iss: 'issuer'
```
