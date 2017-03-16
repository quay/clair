# Clair

[![Build Status](https://api.travis-ci.org/coreos/clair.svg?branch=master "Build Status")](https://travis-ci.org/coreos/clair)
[![Docker Repository on Quay](https://quay.io/repository/coreos/clair/status "Docker Repository on Quay")](https://quay.io/repository/coreos/clair)
[![Go Report Card](https://goreportcard.com/badge/coreos/clair "Go Report Card")](https://goreportcard.com/report/coreos/clair)
[![GoDoc](https://godoc.org/github.com/coreos/clair?status.svg "GoDoc")](https://godoc.org/github.com/coreos/clair)
[![IRC Channel](https://img.shields.io/badge/freenode-%23clair-blue.svg "IRC Channel")](http://webchat.freenode.net/?channels=clair)

**Note**: The `master` branch may be in an *unstable or even broken state* during development.
Please use [releases] instead of the `master` branch in order to get stable binaries.

![Clair Logo](https://cloud.githubusercontent.com/assets/343539/21630811/c5081e5c-d202-11e6-92eb-919d5999c77a.png)

Clair is an open source project for the static analysis of vulnerabilities in application containers (currently including [appc] and [docker]).

Vulnerability data is continuously imported from a known set of sources and correlated with the indexed contents of container images in order to produce lists of vulnerabilities that threaten a container.
When vulnerability data changes upstream, a notification can be delivered, and the API queried to provide the previous state and new state of the vulnerability along with the images affected by both.
All major components can be [extended programmatically] at compile-time without forking the project.

Our goal is to enable a more transparent view of the security of container-based infrastructure.
Thus, the project was named `Clair` after the French term which translates to *clear*, *bright*, *transparent*.

[appc]: https://github.com/appc/spec
[docker]: https://github.com/docker/docker/blob/master/image/spec/v1.2.md
[extended programmatically]: #customization
[releases]: https://github.com/coreos/clair/releases

## Common Use Cases

### Manual Auditing

You're building an application and want to depend on a third-party container image that you found by searching the internet.
To make sure that you do not knowingly introduce a new vulnerability into your production service, you decide to scan the container for vulnerabilities.
You `docker pull` the container to your development machine and start an instance of Clair.
Once it finishes updating, you use the [local image analysis tool] to analyze the container.
You realize this container is vulnerable to many critical CVEs, so you decide to use another one.

[local image analysis tool]: https://github.com/coreos/clair/tree/master/contrib/analyze-local-images

### Container Registry Integration

Your company has a continuous-integration pipeline and you want to stop deployments if they introduce a dangerous vulnerability.
A developer merges some code into the master branch of your codebase.
The first step of your continuous-integration pipeline automates the testing and building of your container and pushes a new container to your container registry.
Your container registry notifies Clair which causes the download and indexing of the images for the new container.
Clair detects some vulnerabilities and sends a webhook to your continuous deployment tool to prevent this vulnerable build from seeing the light of day.

## Hello Heartbleed

During the first run, Clair will bootstrap its database with vulnerability data from its data sources.
It can take several minutes before the database has been fully populated.

**NOTE:** These setups are meant for running HEAD and not production workloads; please use a stable release in production.

### Kubernetes

If you don't have a local Kubernetes cluster already, check out [minikube].

[minikube]: https://github.com/kubernetes/minikube

```
git clone https://github.com/coreos/clair
cd clair/contrib/k8s
kubectl create secret generic clairsecret --from-file=./config.yaml
kubectl create -f clair-kubernetes.yaml
```


### Docker Compose

```sh
$ curl -L https://raw.githubusercontent.com/coreos/clair/master/docker-compose.yml -o $HOME/docker-compose.yml
$ mkdir $HOME/clair_config
$ curl -L https://raw.githubusercontent.com/coreos/clair/master/config.example.yaml -o $HOME/clair_config/config.yaml
$ $EDITOR $HOME/clair_config/config.yaml # Edit database source to be postgresql://postgres:password@postgres:5432?sslmode=disable
$ docker-compose -f $HOME/docker-compose.yml up -d
```

Docker Compose may start Clair before Postgres which will raise an error.
If this error is raised, manually execute `docker-compose start clair`.

### Docker

```sh
$ mkdir $PWD/clair_config
$ curl -L https://raw.githubusercontent.com/coreos/clair/master/config.example.yaml -o $PWD/clair_config/config.yaml
$ docker run -d -e POSTGRES_PASSWORD="" -p 5432:5432 postgres:9.6
$ docker run -d -p 6060-6061:6060-6061 -v $PWD/clair_config:/config quay.io/coreos/clair-git:latest -config=/config/config.yaml
```

### Source

To build Clair, you need to latest stable version of [Go] and a working [Go environment].
In addition, Clair requires that [git], [bzr], [rpm], and [xz] be available on the system [$PATH].

[Go]: https://github.com/golang/go/releases
[Go environment]: https://golang.org/doc/code.html
[git]: https://git-scm.com
[bzr]: http://bazaar.canonical.com/en
[rpm]: http://www.rpm.org
[xz]: http://tukaani.org/xz
[$PATH]: https://en.wikipedia.org/wiki/PATH_(variable)

```sh
$ go get github.com/coreos/clair
$ go install github.com/coreos/clair/cmd/clair
$ $EDITOR config.yaml # Add the URI for your postgres database
$ ./$GOPATH/bin/clair -config=config.yaml
```

### Container images

While container images for every releases are available at [quay.io/repository/coreos/clair], container images built on the latest available source code are available at [quay.io/repository/coreos/clair-git].

[quay.io/repository/coreos/clair]: https://quay.io/repository/coreos/clair
[quay.io/repository/coreos/clair-git]: https://quay.io/repository/coreos/clair-git

## Documentation

The latest stable documentation can be found [on the CoreOS website].
Documentation for the current branch can be found [inside the Documentation directory][docs-dir] at the root of the project's source code.

[on the CoreOS website]: https://coreos.com/clair/docs/latest/
[docs-dir]: /Documentation

### Architecture at a Glance

![Simple Clair Diagram](https://cloud.githubusercontent.com/assets/343539/21630809/c1adfbd2-d202-11e6-9dfe-9024139d0a28.png)

### Terminology

- *Image* - a tarball of the contents of a container
- *Layer* - an *appc* or *Docker* image that may or maybe not be dependent on another image
- *Feature* - anything that when present could be an indication of a *vulnerability* (e.g. the presence of a file or an installed software package)
- *Feature Namespace* - a context around *features* and *vulnerabilities* (e.g. an operating system)
- *Vulnerability Updater* - a Go package that tracks upstream vulnerability data and imports them into Clair
- *Vulnerability Metadata Appender* - a Go package that tracks upstream vulnerability metadata and appends them into vulnerabilities managed by Clair

### Vulnerability Analysis

There are two major ways to perform analysis of programs: [Static Analysis] and [Dynamic Analysis].
Clair has been designed to perform *static analysis*; containers never need to be executed.
Rather, the filesystem of the container image is inspected and *features* are indexed into a database.
By indexing the features of an image into the database, images only need to be rescanned when new *detectors* are added.

[Static Analysis]: https://en.wikipedia.org/wiki/Static_program_analysis
[Dynamic Analysis]: https://en.wikipedia.org/wiki/Dynamic_program_analysis

### Default Data Sources

| Data Source                   | Data Collected                                                           | Format | License         |
|-------------------------------|--------------------------------------------------------------------------|--------|-----------------|
| [Debian Security Bug Tracker] | Debian 6, 7, 8, unstable namespaces                                      | [dpkg] | [Debian]        |
| [Ubuntu CVE Tracker]          | Ubuntu 12.04, 12.10, 13.04, 14.04, 14.10, 15.04, 15.10, 16.04 namespaces | [dpkg] | [GPLv2]         |
| [Red Hat Security Data]       | CentOS 5, 6, 7 namespaces                                                | [rpm]  | [CVRF]          |
| [Oracle Linux Security Data]  | Oracle Linux 5, 6, 7 namespaces                                          | [rpm]  | [CVRF]          |
| [Alpine SecDB]                | Alpine 3.3, Alpine 3.4, Alpine 3.5 namespaces                            | [apk]  | [MIT]           |
| [NIST NVD]                    | Generic Vulnerability Metadata                                           | N/A    | [Public Domain] |

[Debian Security Bug Tracker]: https://security-tracker.debian.org/tracker
[Ubuntu CVE Tracker]: https://launchpad.net/ubuntu-cve-tracker
[Red Hat Security Data]: https://www.redhat.com/security/data/metrics
[Oracle Linux Security Data]: https://linux.oracle.com/security/
[NIST NVD]: https://nvd.nist.gov
[dpkg]: https://en.wikipedia.org/wiki/dpkg
[rpm]: http://www.rpm.org
[Debian]: https://www.debian.org/license
[GPLv2]: https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html
[CVRF]: http://www.icasi.org/cvrf-licensing/
[Public Domain]: https://nvd.nist.gov/faq
[Alpine SecDB]: http://git.alpinelinux.org/cgit/alpine-secdb/
[apk]: http://git.alpinelinux.org/cgit/apk-tools/
[MIT]: https://gist.github.com/jzelinskie/6da1e2da728424d88518be2adbd76979


### Customization

The major components of Clair are all programmatically extensible in the same way Go's standard [database/sql] package is extensible.
Everything extendable is located in the `ext` directory.

Custom behavior can be accomplished by creating a package that contains a type that implements an interface declared in Clair and registering that interface in [init()].
To expose the new behavior, unqualified imports to the package must be added in your own custom [main.go], which should then start Clair using `Boot(*config.Config)`.

[database/sql]: https://godoc.org/database/sql
[init()]: https://golang.org/doc/effective_go.html#init
[main.go]: https://github.com/coreos/clair/blob/master/cmd/clair/main.go

## Related Links

### Talks & Slides

- _Clair: The Container Image Security Analyzer @ ContainerDays Boston 2016_ - [Event](http://dynamicinfradays.org/events/2016-boston/) [Video](https://www.youtube.com/watch?v=Kri67PtPv6s) [Slides](https://docs.google.com/presentation/d/1ExQGZs-pQ56TpW_ifcUl2l_ml87fpCMY6-wdug87OFU)
- _Identifying Common Vulnerabilities and Exposures in Containers with Clair @ CoreOS Fest 2016_ - [Event](https://coreos.com/fest/) [Video](https://www.youtube.com/watch?v=YDCa51BK2q0) [Slides](https://docs.google.com/presentation/d/1pHSI_5LcjnZzZBPiL1cFTZ4LvhzKtzh86eE010XWNLY)
- _Clair: A Container Image Security Analyzer @  Microservices NYC_ - [Event](https://www.meetup.com/Microservices-NYC/events/230023492/) [Video](https://www.youtube.com/watch?v=ynwKi2yhIX4) [Slides](https://docs.google.com/presentation/d/1ly9wQKQIlI7rlb0JNU1_P-rPDHU4xdRCCM3rxOdjcgc)
- _Clair: A Container Image Security Analyzer @ Container Orchestration NYC_ - [Event](https://www.meetup.com/Container-Orchestration-NYC/events/229779466/) [Video](https://www.youtube.com/watch?v=wTfCOUDNV_M) [Slides](https://docs.google.com/presentation/d/1ly9wQKQIlI7rlb0JNU1_P-rPDHU4xdRCCM3rxOdjcgc)

### Integrations and Production Users

- [Projects integrating with Clair](https://github.com/coreos/clair/blob/master/Documentation/integrations.md)
- [Production users](https://github.com/coreos/clair/blob/master/Documentation/production-users.md)

