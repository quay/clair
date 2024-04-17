#!/bin/bash
set -exuo pipefail

: "${QUAY_USER:?Missing QUAY_USER variable.}"
: "${QUAY_TOKEN:?Missing QUAY_TOKEN variable.}"
: "${REGISTRY:=quay.io}"
: "${REPOSITORY:=${REGISTRY}/app-sre}"
: "${IMAGE:=${REPOSITORY}/clair}"
GIT_HASH="$(git rev-parse --short=7 HEAD)"
CONTAINER_ENGINE=$(command -v podman 2>/dev/null || command -v docker 2>/dev/null)

git archive HEAD |
	${CONTAINER_ENGINE} build -t clair-service:latest -

${CONTAINER_ENGINE} login -u="${QUAY_USER}" -p="${QUAY_TOKEN}" "${REGISTRY}"

${CONTAINER_ENGINE} tag clair-service:latest ${IMAGE}:latest
${CONTAINER_ENGINE} push ${IMAGE}:latest

${CONTAINER_ENGINE} tag clair-service:latest ${IMAGE}:${GIT_HASH}
${CONTAINER_ENGINE} push ${IMAGE}:${GIT_HASH}
