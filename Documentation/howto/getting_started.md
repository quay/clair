# Getting Started With ClairV4

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

The easiest way to get ClairV4 up and running for test purposes is to use our [local dev environment](./testing.md)

If you're the hands on type who wants to get into the details however, continue reading.

## ClairV4 Modes

ClairV4 can run in several modes. [Indexer](../reference/indexer.md), [matcher](../reference/matcher.md), [notifier](../reference/notifier.md) or combo mode. In combo mode all of the mentioned node types ran in a single process. 

If you are just starting with ClairV4 you will most likely want to continue with combo mode and venture out to a distributed deployment once acquainted. 

This how-to will demonstrate combo mode and introduce some further reading on a distributed deployment.

## Postgres

ClairV4 uses Postgres for its data persistence. Migrations are supported so you should only need to point ClairV4 to a fresh database and have it do the setup for you.

We will assume you have setup a postgres database its reachable with the following connection string:
`host=clair-db port=5432 user=clair dbname=clair sslmode=disable`. Adjust for your environment accordingly. 

## Starting ClairV4 In Combo Mode

At this point you either have built ClairV4 from source or you have the ClairV4 container pulled. In either case we will assume that the clair-db hostname can be resolved to your postgres database. 

*You may need to configure [docker](https://docs.docker.com/network/) or [podman](https://podman.io/getting-started/network.html) networking if you are utilizing containers. This is out of scope for this how too.*

A basic config for combo mode can be found [here](https://github.com/quay/clair/blob/development-4.0/config.yaml.sample). Make sure to edit this config with your database settings and flip "migrations" on for all node types. In combo mode all "connstring" field should point to the same database and any *_addr fields are simply ignored. For more details see the [config reference](../reference/config.md) and [deployment models](./deployment.md)

Clair has 3 requirements to start:
* a mode cli flag or CLAIR_MODE env variable telling what node type this Clair will run as.
* a conf cli flag or CLAIR_CONF env variable telling where Clair can find its configuration.
* a structured yaml config providing the bulk of Clair's configuration.

If you are running a container you can can [mount](https://docs.docker.com/storage/volumes/) a clair config to any readable path you like and set the env vars to:
```
CLAIR_MODE=combo
CLAIR_CONF=/path/to/mounted/config.yaml
```

If you are running Clair from a built binary its likely easiest to issue the following command line
```
clair -conf "path/to/config.yaml" -mode "combo"
```

## Submitting A Manifest

The simplest way to submit a manifest to your running Clair is utilizing [clairctl](../reference/clairctl.md). This is a CLI tool capable of grabbing images from public repositories and and submitting them to ClairV4 for analysis. 
This CLI will be in your ClairV4 container and can also be installed by running the following command:
```
go install github.com/quay/clair/v4/cmd/clairctl
```

You can submit a manifest to ClairV4 via the following command.
```shell
$ clairctl --host {net_address_of_clair} report {image:tag}
```

By default the tool will look for clair at `localhost:6060` (our local development address) but you may change this.

If all things look good you should see some output like the following informting you of vulnerabilities affecting the supplied image.

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

## Whats Next

Now that you see the basic usage of ClairV4 you can checkout our [deployment models](./deployment.md) to learn different ways of deploing ClairV4.

You may also be curious about how clairctl did that work. Check out out [api definition](./api.md) to understand how an application would interact with ClairV4 without a client.
