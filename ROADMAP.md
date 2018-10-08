# Clair Roadmap

This document defines a high level roadmap for Clair development.

The dates below should not be considered authoritative, but rather indicative of the projected timeline of the project.
The [milestones defined in GitHub](https://github.com/coreos/clair/milestones) represent the most up-to-date and issue-for-issue plans.

The roadmap below outlines new features that will be added to Clair, and while subject to change, define what future stable will look like.

- Support multiple namespaces per image
  - This enables language-level package managers (e.g. npm, pip) in the future
- Take advantage of OCI/Docker content-addressiblity to avoid duplicated work
  - This simplifies the amount of work required for an offline clair in the future
- Support mappings between source packages and binary packages
- Versioned detectors that are present in API results
  - This will enable clients to determine when images need to be reindexed
- gRPC API that works on sets of layers rather than individual layers
- Structured logging in JSON
- Improve coverage and readability of documentation
