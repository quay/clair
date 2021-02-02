#!/bin/bash

set -exv
REPOSITORY="quay.io/app-sre"
IMAGE="${REPOSITORY}/clair"

make container-build

GIT_HASH=`git rev-parse --short=7 HEAD`
skopeo copy --dest-creds "${QUAY_USER}:${QUAY_TOKEN}" \
    "docker-daemon:clair-local:latest" \
    "docker://${IMAGE}:latest"

skopeo copy --dest-creds "${QUAY_USER}:${QUAY_TOKEN}" \
    "docker-daemon:clair-local:latest" \
    "docker://${IMAGE}:${GIT_HASH}"
