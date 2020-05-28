#!/bin/bash

set -exv
REPOSITORY="quay.io/app-sre"
IMAGE="${REPOSITORY}/clair"

docker run --user="$(id -u):$(id -g)" -v $(pwd):/go/clair:z -e GOCACHE=/go/clair golang:1.14.1-buster "bash" "-c" "cd /go/clair; ls -la; go mod vendor"
make container-build

GIT_HASH=`git rev-parse --short=7 HEAD`
skopeo copy --dest-creds "${QUAY_USER}:${QUAY_TOKEN}" \
    "docker-daemon:clair-local:latest" \
    "docker://${IMAGE}:latest"

skopeo copy --dest-creds "${QUAY_USER}:${QUAY_TOKEN}" \
    "docker-daemon:clair-local:latest" \
    "docker://${IMAGE}:${GIT_HASH}"
