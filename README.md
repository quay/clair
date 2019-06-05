# Clair

[![Build Status](https://api.travis-ci.org/coreos/clair.svg?branch=master "Build Status")](https://travis-ci.org/coreos/clair)
[![Docker Repository on Quay](https://quay.io/repository/coreos/clair/status "Docker Repository on Quay")](https://quay.io/repository/coreos/clair)
[![Go Report Card](https://goreportcard.com/badge/coreos/clair "Go Report Card")](https://goreportcard.com/report/coreos/clair)
[![GoDoc](https://godoc.org/github.com/coreos/clair?status.svg "GoDoc")](https://godoc.org/github.com/coreos/clair)
[![IRC Channel](https://img.shields.io/badge/freenode-%23clair-blue.svg "IRC Channel")](http://webchat.freenode.net/?channels=clair)

**Note**: The `master` branch may be in an *unstable or even broken state* during development.
Please use [releases] instead of the `master` branch in order to get stable binaries.

![Clair Logo](https://cloud.githubusercontent.com/assets/343539/21630811/c5081e5c-d202-11e6-92eb-919d5999c77a.png)

Clair is an open source project for the [static analysis] of vulnerabilities in application containers (currently including [appc] and [docker]).

1. In regular intervals, Clair ingests vulnerability metadata from a configured set of sources and stores it in the database.
2. Clients use the Clair API to index their container images; this creates a list of _features_ present in the image and stores them in the database.
3. Clients use the Clair API to query the database for vulnerabilities of a particular image; correlating vulnerabilities and features is done for each request, avoiding the need to rescan images.
4. When updates to vulnerability metadata occur, a notification can be sent to alert systems that a change has occured.

Our goal is to enable a more transparent view of the security of container-based infrastructure.
Thus, the project was named `Clair` after the French term which translates to *clear*, *bright*, *transparent*.

[appc]: https://github.com/appc/spec
[docker]: https://github.com/docker/docker/blob/master/image/spec/v1.2.md
[releases]: https://github.com/coreos/clair/releases
[static analysis]: https://en.wikipedia.org/wiki/Static_program_analysis

## Getting Started

* Learn [the terminology] and about the [drivers and data sources] that power Clair
* Watch [presentations] on the high-level goals and design of Clair
* Follow instructions to get Clair [up and running]
* Explore [the API] on SwaggerHub
* Discover third party [integrations] that help integrate Clair with your infrastructure
* Read the rest of the documentation on the [CoreOS website] or in the [Documentation directory]
* Get up and running with [Local Development]

[the terminology]: /Documentation/terminology.md
[drivers and data sources]: /Documentation/drivers-and-data-sources.md
[presentations]: /Documentation/presentations.md
[up and running]: /Documentation/running-clair.md
[the API]: https://app.swaggerhub.com/apis/coreos/clair/3.0
[integrations]: /Documentation/integrations.md
[CoreOS website]: https://coreos.com/clair/docs/latest/
[Documentation directory]: /Documentation
[Local Development]: /Documentation/local-development.md

## Community

- Mailing List: [clair-dev@googlegroups.com](https://groups.google.com/forum/#!forum/clair-dev)
- IRC: #[clair](irc://irc.freenode.org:6667/#clair) on freenode.org
- Bugs: [issues](https://github.com/coreos/clair/issues)

## Contributing

See [CONTRIBUTING](.github/CONTRIBUTING.md) for details on submitting patches and the contribution workflow.

## License

Clair is under the Apache 2.0 license. See the [LICENSE](LICENSE) file for details.
