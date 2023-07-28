# Clair

[![Docker Repository on Quay](https://quay.io/repository/projectquay/clair/status "Docker Repository on Quay")](https://quay.io/repository/projectquay/clair)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/quay/clair/v4 "Go Documentation")](https://pkg.go.dev/github.com/quay/clair/v4)
[![IRC Channel](https://img.shields.io/badge/freenode-%23clair-blue.svg "IRC Channel")](http://webchat.freenode.net/?channels=clair)

**Note**: The `main` branch may be in an *unstable or even broken state* during development.
Please use [releases] instead of the `main` branch in order to get stable binaries.

![Clair Logo](https://cloud.githubusercontent.com/assets/343539/21630811/c5081e5c-d202-11e6-92eb-919d5999c77a.png)

Clair is an open source project for the [static analysis] of vulnerabilities in
application containers (currently including [OCI] and [docker]).

Clients use the Clair API to index their container images and can then match it against known vulnerabilities.

Our goal is to enable a more transparent view of the security of container-based infrastructure.
Thus, the project was named `Clair` after the French term which translates to *clear*, *bright*, *transparent*.

[The book] contains all the documentation on Clair's architecture and operation.

[OCI]: https://github.com/opencontainers/image-spec/blob/master/spec.md
[docker]: https://github.com/docker/docker/blob/master/image/spec/v1.2.md
[releases]: https://github.com/quay/clair/releases
[static analysis]: https://en.wikipedia.org/wiki/Static_program_analysis
[The book]: https://quay.github.io/clair/

## Community

- Mailing List: [clair-dev@googlegroups.com](https://groups.google.com/forum/#!forum/clair-dev)
- IRC: #[clair](irc://irc.freenode.org:6667/#clair) on freenode.org
- Bugs: [issues](https://github.com/quay/clair/issues)

## Contributing

See [CONTRIBUTING](.github/CONTRIBUTING.md) for details on submitting patches and the contribution workflow.

## License

Clair is under the Apache 2.0 license. See the [LICENSE](LICENSE) file for details.
