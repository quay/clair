#!/bin/bash
set -exuo pipefail

: "${QUAY_USER:?Missing QUAY_USER variable.}"
: "${QUAY_TOKEN:?Missing QUAY_TOKEN variable.}"
: "${REGISTRY:=quay.io}"
: "${REPOSITORY:=${REGISTRY}/app-sre}"
: "${IMAGE:=${REPOSITORY}/clair}"
GIT_HASH="$(git rev-parse --short=7 HEAD)"

git archive HEAD |
	podman build -t clair-service:latest -

podman login -u="${QUAY_USER}" -p="${QUAY_TOKEN}" "${REGISTRY}"

podman push clair-service:latest docker://${IMAGE}:latest
podman push clair-service:latest docker://${IMAGE}:${GIT_HASH}
