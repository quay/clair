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
clairctl export-updaters updates.json.gz
```

```sh
# Move the resulting file to a place reachable by the cluster:
scp updates.json.gz internal-webserver:/var/www/
```

```sh
# On a pod inside the cluster, import the file:
clairctl import-updaters http://web.svc/updates.json.gz
```

Note that a configuration file is needed to run these commands.

#### Configuration

Matcher processes should have the `disable_updaters` key set to disable
automatic updaters running.

```yaml
matcher:
  disable_updaters: true
```

## Indexers

### Configuration

#### Airgap

```yaml
indexer:
  airgap: true
```

#### Specific Scanners

```yaml
indexer:
  scanner:
    package:
      name:
        key: value
    repo:
      name:
        key: value
    dist:
      name:
        key: value
```

