# syntax=docker/dockerfile:1

# Note that building this with `podman` or `buildah` requires the "docker"
# format, as does the container using it. Using `docker` should be fine, but
# YMMV.

# The following needs to be kept in sync with the main Dockerfile.
ARG GO_VERSION=1.17
FROM quay.io/projectquay/golang:${GO_VERSION} AS build
WORKDIR /build/
ONBUILD COPY go.mod go.sum /build/
ONBUILD RUN go mod download
ONBUILD COPY . /build/
ONBUILD RUN go build -trimpath -buildmode=plugin ./
