#!/usr/bin/bash
set -euo pipefail

while getopts nx name; do
	case "$name" in
	x) set -x ;;
	n) dryrun=1 ;;
	?)
		printf "Usage: %s: [-nx]\n" "$0"
		exit 2
		;;
	esac
done

: "${REGISTRY:=quay.io}"
: "${REPOSITORY:=${REGISTRY}/app-sre}"
: "${IMAGE:=${REPOSITORY}/clair}"
GIT_HASH="$(git rev-parse --short=7 HEAD)"
CONTAINER_ENGINE=$(command -v podman 2>/dev/null || command -v docker 2>/dev/null)
tags=("${IMAGE}:latest" "${IMAGE}:${GIT_HASH}")

git archive HEAD |
	${CONTAINER_ENGINE} build -t clair-service:latest -
for t in "${tags[@]}"; do
	${CONTAINER_ENGINE} tag clair-service:latest "$t"
done

[[ -n "$dryrun" ]] && exit 0

: "${QUAY_USER:?Missing QUAY_USER variable.}"
: "${QUAY_TOKEN:?Missing QUAY_TOKEN variable.}"
${CONTAINER_ENGINE} login -u="${QUAY_USER}" -p="${QUAY_TOKEN}" "${REGISTRY}"
for t in "${tags[@]}"; do
	${CONTAINER_ENGINE} push "$t"
done
