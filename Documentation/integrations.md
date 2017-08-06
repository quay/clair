# Integrations

This document tracks projects that integrate with Clair. [Join the community](https://github.com/coreos/clair/), and help us keep the list up-to-date.

## Projects

[Quay.io](https://quay.io/) and [Quay Enterprise](https://quay.io/plans/?tab=enterprise): Quay was the first container registry to integrate with Clair.

[Dockyard](https://github.com/Huawei/dockyard): an open source container registry with Clair integration.

[Clairctl](https://github.com/jgsqware/clairctl): a lightweight command-line tool for working locally with Clair and generate HTML report.

[Clair-SQS](https://github.com/zalando-incubator/clair-sqs): a container containing Clair and additional processes that integrate Clair with [Amazon SQS][sqs].

[Klar](https://github.com/optiopay/klar): a simple command-line integration of Clair and Docker registry, designed to be used in scripts and CI.

[reg](https://github.com/jessfraz/reg#vulnerability-reports): a docker registry CLI, which also runs Clair.

[analyze-local-images](https://github.com/coreos/analyze-local-images): a deprecated tool to analyze local Docker images

[check_openvz_mirror_with_clair](https://github.com/FastVPSEestiOu/check_openvz_mirror_with_clair): a tool to use Clair to analyze OpenVZ templates

[Portus](http://port.us.org/features/6_security_scanning.html#coreos-clair): an authorization service and frontend for Docker registry (v2).

[clair-scanner](https://github.com/arminc/clair-scanner): a spin-off from 'analyze-local-images' who blocks on vulnerabilities with whitelist possibility

[sqs]: https://aws.amazon.com/sqs/
