# Integrations

This document tracks projects that integrate with Clair. [Join the community](https://github.com/coreos/clair/), and help us keep the list up-to-date.

## Projects

[Quay.io](https://quay.io/) and [Quay Enterprise](https://quay.io/plans/?tab=enterprise): Quay was the first container registry to integrate with Clair.

[Dockyard](https://github.com/Huawei/dockyard): an open source container registry with Clair integration.

[Yair](https://github.com/yfoelling/yair): a lightweight command-line for working with clair with many different outputs. Mainly designed for usage in a CI Job.

[Claircli](https://github.com/joelee2012/claircli):  A simple cmd tool to interact with CoreOS Clair.

[Paclair](https://github.com/yebinama/paclair): a Python3 CLI tool to interact with Clair (easily configurable to access private registries).

[Clairctl](https://github.com/jgsqware/clairctl): a lightweight command-line tool for working locally with Clair and generate HTML report.

[Clair-SQS](https://github.com/zalando-incubator/clair-sqs): a container containing Clair and additional processes that integrate Clair with [Amazon SQS][sqs].

[Klar](https://github.com/optiopay/klar): a simple command-line integration of Clair and Docker registry, designed to be used in scripts and CI.

[reg](https://github.com/jessfraz/reg#vulnerability-reports): a docker registry CLI, which also runs Clair.

[analyze-local-images](https://github.com/coreos/analyze-local-images): a deprecated tool to analyze local Docker images

[check_openvz_mirror_with_clair](https://github.com/FastVPSEestiOu/check_openvz_mirror_with_clair): a tool to use Clair to analyze OpenVZ templates

[Portus](http://port.us.org/features/6_security_scanning.html#coreos-clair): an authorization service and frontend for Docker registry (v2).

[clair-scanner](https://github.com/arminc/clair-scanner): a project similar to 'analyze-local-images' with a whitelisting feature

[sqs]: https://aws.amazon.com/sqs/

[clair-singularity](https://github.com/dctrud/clair-singularity): a command-line tool to scan [Singularity](http://singularity.lbl.gov/) container images using Clair.
