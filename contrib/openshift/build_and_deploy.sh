#!/bin/bash

set -exv
REPOSITORY="quay.io/app-sre"
IMAGE="${REPOSITORY}/clair"

docker build --build-arg CLAIR_VERSION=${GIT_HASH} -t clair-service:latest .

GIT_HASH=`git rev-parse --short=7 HEAD`
skopeo copy --dest-creds "${QUAY_USER}:${QUAY_TOKEN}" \
    "docker-daemon:clair-service:latest" \
    "docker://${IMAGE}:latest"

skopeo copy --dest-creds "${QUAY_USER}:${QUAY_TOKEN}" \
    "docker-daemon:clair-service:latest" \
    "docker://${IMAGE}:${GIT_HASH}"
