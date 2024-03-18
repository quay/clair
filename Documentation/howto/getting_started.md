# Getting Started With Clair

## Releases

All of the source code needed to build clair is packaged as an archive and
attached to the release. Releases are tracked at the [github releases].

The release artifacts also include the clairctl command line tool.

[github releases]: https://github.com/quay/clair/releases

## Official Containers

Clair is officially packaged and released as a container at
[quay.io/projectquay/clair]. The `latest` tag tracks the git development branch,
and version tags are built from the corresponding release.

[quay.io/projectquay/clair]: https://quay.io/repository/projectquay/clair

## Running Clair

The easiest way to get Clair up and running for test purposes is to use our [local dev environment](./testing.md)

If you're the hands on type who wants to get into the details however, continue reading.

## Modes

Clair can run in several modes. [Indexer](../reference/indexer.md), [matcher](../reference/matcher.md), [notifier](../reference/notifier.md) or combo mode. In combo mode, everything runs in a single OS process. 

If you are just starting with Clair you will most likely want to start with combo mode and venture out to a distributed deployment once acquainted. 

This how-to will demonstrate combo mode and introduce some further reading on a distributed deployment.

## Postgres

Clair uses PostgreSQL for its data persistence. Migrations are supported so you should only need to point Clair to a fresh database and have it do the setup for you.

We will assume you have setup a postgres database and it's reachable with the following connection string:
`host=clair-db port=5432 user=clair dbname=clair sslmode=disable`. Adjust for your environment accordingly. 

## Starting Clair In Combo Mode

At this point, you should either have built Clair from source or have pulled the container. In either case, we will assume that the `clair-db` hostname will resolve to your postgres database. 

*You may need to configure [docker](https://docs.docker.com/network/) or [podman](https://podman.io/getting-started/network.html) networking if you are utilizing containers. This is out of scope for this how-to.*

A basic config for combo mode can be found [here](https://github.com/quay/clair/blob/main/config.yaml.sample). Make sure to edit this config with your database settings and set "migrations" to `true` for all mode stanzas. In this basic combo mode, all "connstring" fields should point to the same database and any *_addr fields are simply ignored. For more details see the [config reference](../reference/config.md) and [deployment models](./deployment.md)

Clair has 3 requirements to start:
* The `mode` flag or `CLAIR_MODE` environment variable specifying what mode this instance will run in.
* The `conf` flag or `CLAIR_CONF` environment variable specifying where Clair can find its configuration.
* A yaml document providing Clair's configuration.

If you are running a container, you can [mount](https://docs.docker.com/storage/volumes/) a Clair config and set the `CLAIR_CONF` environment variable to the corresponding path.
```
CLAIR_MODE=combo
CLAIR_CONF=/path/to/mounted/config.yaml
```

If you are running a Clair binary directly, its likely easiest to use the command line.
```
clair -conf "path/to/config.yaml" -mode "combo"
```

## Submitting A Manifest

The simplest way to submit a manifest to your running Clair is utilizing [clairctl](../reference/clairctl.md). This is a CLI tool capable of grabbing image manifests from public repositories and submitting them for analysis. 
The command will be in the Clair container, but can also be installed locally by running the following command:
```
go install github.com/quay/clair/v4/cmd/clairctl@latest
```

You can submit a manifest to ClairV4 via the following command.
```shell
$ clairctl report --host ${net_address_of_clair} ${image_tag}
```
You will need to add the `config` flag if you are using a PSK authentication (as in the [local dev environment](./testing.md) setup, for example).
```shell
$ clairctl report --config local-dev/clair/config.yaml --host ${net_address_of_clair} ${image_tag}
```
By default, `clairctl` will look for Clair at `localhost:6060` or the environment variable `CLAIR_API`, and for a configuration at `config.yaml` or the environment variable `CLAIR_CONF`.

If everything is configured correctly, you should see some output like the following informing you of vulnerabilities affecting the supplied image.

```shell
$ clairctl report ubuntu:focal
ubuntu:focal found bash        5.0-6ubuntu1.1         CVE-2019-18276
ubuntu:focal found libpcre3    2:8.39-12build1        CVE-2017-11164
ubuntu:focal found libpcre3    2:8.39-12build1        CVE-2019-20838
ubuntu:focal found libpcre3    2:8.39-12build1        CVE-2020-14155
ubuntu:focal found libsystemd0 245.4-4ubuntu3.2       CVE-2018-20839
ubuntu:focal found libsystemd0 245.4-4ubuntu3.2       CVE-2020-13776
ubuntu:focal found libtasn1-6  4.16.0-2               CVE-2018-1000654
ubuntu:focal found libudev1    245.4-4ubuntu3.2       CVE-2018-20839
ubuntu:focal found libudev1    245.4-4ubuntu3.2       CVE-2020-13776
ubuntu:focal found login       1:4.8.1-1ubuntu5.20.04 CVE-2013-4235
ubuntu:focal found login       1:4.8.1-1ubuntu5.20.04 CVE-2018-7169
ubuntu:focal found coreutils   8.30-3ubuntu2          CVE-2016-2781
ubuntu:focal found passwd      1:4.8.1-1ubuntu5.20.04 CVE-2013-4235
ubuntu:focal found passwd      1:4.8.1-1ubuntu5.20.04 CVE-2018-7169
ubuntu:focal found perl-base   5.30.0-9build1         CVE-2020-10543
ubuntu:focal found perl-base   5.30.0-9build1         CVE-2020-10878
ubuntu:focal found perl-base   5.30.0-9build1         CVE-2020-12723
ubuntu:focal found tar         1.30+dfsg-7            CVE-2019-9923
ubuntu:focal found dpkg        1.19.7ubuntu3          CVE-2017-8283
ubuntu:focal found gpgv        2.2.19-3ubuntu2        CVE-2019-13050
ubuntu:focal found libc-bin    2.31-0ubuntu9          CVE-2016-10228
ubuntu:focal found libc-bin    2.31-0ubuntu9          CVE-2020-6096
ubuntu:focal found libc6       2.31-0ubuntu9          CVE-2016-10228
ubuntu:focal found libc6       2.31-0ubuntu9          CVE-2020-6096
ubuntu:focal found libgcrypt20 1.8.5-5ubuntu1         CVE-2019-12904
```

To test locally-built images, you'll need to push them to a registry that is accessible by the Clair service and the `clairctl` command.
A local registry can be used for this, but the specifics of configuration vary by registry and container runtime.
Consult the relevant documentation for more information.

## What's Next

Now that you see the basic usage of Clair, you can checkout our [deployment models](./deployment.md) to learn different ways of deploying.

You may also be curious about how `clairctl` did that work. Check out our [API definition](./api.md) to understand how an application interacts with Clair.
