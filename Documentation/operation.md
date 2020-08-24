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

## Updaters

Clair utilizes go packages we call "updaters" that encapsulate the logic of
fetching and parsing different vulnerability databases. Updaters are usually
pared with a matcher to interpret if and how any vulnerability is related to a
package.

Operators may wish to update the vulnerability database less frequently or not
import vulnerabilities from databases that they know will not be used.

### Configuration

Updaters can be configured by `updaters` key at the top of the configuration. If
updaters are being run automatically within the matcher processes, as is the
default, the period for running updaters is configured under the matcher's
configuration stanza.

#### Choosing Sets

Specific sets of updaters can be selected by the `sets` list. If not present,
the defaults of all upstream updaters will be used.

```yaml
updaters:
  sets:
    - rhel
```

#### Filtering Updaters

To disallow an updater from running without disabling an entire set, the filter
option can be used. The provided string will be interpreted as a go [regexp]
used to disallow any updater with a name that does not match. **Note:** This
means that an empty string matches *any* string, not no strings.

```yaml
updaters:
  filter: '^$'
```

#### Specific Updaters

Configuration for specific updaters can be passed by putting a key underneath
the `config` member of the `updaters` object. The name of an updater may be
constructed dynamically; users should examine logs to double-check names.
The specific object that an updater expects should be covered in the updater's
documentation.

For example, to have the "rhel" updater fetch a manifest from a different
location:

```yaml
updaters:
  config:
    rhel:
      url: https://example.com/mirror/oval/PULP_MANIFEST
```

### Airgap

For additional flexibility, Clair supports running updaters in a different
environment and importing the results. This is aimed at supporting installations
that disallow the Clair cluster from talking to the Internet directly. An update
procedure needs to arrange to call the relevant `clairctl` command in an
environment with access to the Internet, move the resulting artifact across the
airgap according to site policy, and then call the relevant `clairctl` command
to import the updates.

For example:

```sh
# On a workstation, run:
clairctl updater-export updates.gz
```

```sh
# Move the resulting file to a place reachable by the cluster:
scp updates.gz internal-webserver:/var/www/
```

```sh
# On a pod inside the cluster, import the file:
clairctl updater-import http://web.svc/updates.gz
```

#### Configuration

Matcher processes should have the `disable_updaters` key set to disable
automatic updaters running.

```yaml
matcher:
  disable_updaters: true
```

Desired updaters should be selected by the normal configuration mechanism.

## Indexers

#### Configuration
