# Building

This repo is intended to be built with familiar `go build` or `go install` invocations.
All binaries (excepting debugging tools) are underneath the `cmd` directory.

### Cross-compiling

Currently Clair does not have any cgo dependencies, so there should not be any cross-compilation concerns.

## Container

A `Dockerfile` for the project is in the repo root.
**The only upstream-supported means of using it is Buildkit via `buildctl`.**
See the `container`, `container-build`, `dist-container`, and `dist-clairctl` make targets for example invocations.
The `BUILDKIT_HOST` environment variable may need to be set, depending on how `buildkitd` is running in one's environment.
