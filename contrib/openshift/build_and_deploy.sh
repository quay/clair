#!/usr/bin/bash
set -euo pipefail

splice() { local IFS="$1"; shift; echo "$*"; }

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
: "${NAMESPACE:=app-sre}"
: "${REPOSITORY:=clair}"
: "${IMAGE:=$(splice / "$REGISTRY" "$NAMESPACE" "$REPOSITORY")}"
: "${BUILDKIT_IMAGE:=$(splice / "$REGISTRY" "$NAMESPACE" buildkit:latest)}"
: "${CONTAINER_ENGINE:=$(command -v podman 2>/dev/null || command -v docker 2>/dev/null)}"
: "${cidfile:=buildkit.cid}"
GIT_HASH="$(git rev-parse --short=7 HEAD)"
tags=("${IMAGE}:latest" "${IMAGE}:${GIT_HASH}")
trap 'rm -rf clair-v*.{tar*,oci}' ERR

patch_source() {
	in=$1
	if [[ $(tar tf "$in" '*/Dockerfile' | wc -l) -ne 1 ]]; then
		echo already patched >&2
		return
	fi

	( # Subshell to set a cleanup trap.
	tmp=$(mktemp -d)
	trap 'rm -r "$tmp"' EXIT
	gunzip "$in"
	in=${in%.gz}

	filename=$(tar tf "$in" '*/Dockerfile')
	tar -xOf "$in" "$filename" |
		sed "s,docker.io/[[:alpha:]]\+,$(splice / "$REGISTRY" "$NAMESPACE")," >"${tmp}/Dockerfile"
	tar -rf "$in" --transform "s,.*,${filename}," "${tmp}/Dockerfile"
	gzip -n -q -f "$in"
	)
}

if [[ -d bin ]]; then
	PATH=$(realpath bin):${PATH}
fi
if ! command -v buildctl >/dev/null 2>&1; then
	echo Fetching buildctl:
	: "${BUILDCTL_VERSION:=0.15.0}"
	mkdir -p bin
	PATH=$(realpath bin):${PATH}
	curl -sSfL "https://github.com/moby/buildkit/releases/download/v${BUILDCTL_VERSION}/buildkit-v${BUILDCTL_VERSION}.linux-amd64.tar.gz" |
		tar -xzC bin --strip-components=1 bin/buildctl
	command -V buildctl
	buildctl --version
fi

echo Starting buildkitd container:
cleanup() {
	echo Stopping buildkitd container:
	${CONTAINER_ENGINE} stop --cidfile "${cidfile}" || echo Failed to stop buildkit container >&2
	if [[ -f "${cidfile}" ]]; then
		rm "${cidfile}" || echo Unable to remove cidfile: "${cidfile}" >&2
	fi
}

# Unconditionally log in if we have credentials because AppSRE CI can't be
# bothered to clear them between Jenkins jobs.
if [[ -n "${QUAY_USER-}" && -n "${QUAY_TOKEN-}" ]]; then
	skopeo login -u="${QUAY_USER}" -p="${QUAY_TOKEN}" "${REGISTRY}"
fi
${CONTAINER_ENGINE} run \
	--cidfile "${cidfile}" \
	--detach \
	--privileged \
	--rm \
	"${BUILDKIT_IMAGE}"
trap 'cleanup' EXIT
BUILDKIT_HOST="$(basename "${CONTAINER_ENGINE}")-container://$(cat "$cidfile")"
export BUILDKIT_HOST

echo Exporting source:
make dist

echo Applying self-inflicted wound:
if [[ $(find . -maxdepth 1 -type f -name 'clair-v*.tar*' | wc -l) -ne 1 ]]; then
	echo found multiple dist tarballs, exiting: "$(ls clair-v*.tar*)" >&2
	exit 99
fi
patch_source clair-v*.tar.gz

echo Building container:
make "IMAGE_NAME=$(splice , "${tags[@]}")" dist-container

# Make repeated runs work more-or-less correctly.
touch -m -t 197001010000 clair-v*.{tar.gz,oci}

[[ -n "${dryrun-}" ]] && exit 0

if ! skopeo login --get-login "${REGISTRY}" >/dev/null; then
	: "${QUAY_USER:?Missing QUAY_USER variable.}"
	: "${QUAY_TOKEN:?Missing QUAY_TOKEN variable.}"
	skopeo login -u="${QUAY_USER}" -p="${QUAY_TOKEN}" "${REGISTRY}"
fi
ar=$(echo clair-v4.*.oci)
for t in "${tags[@]}"; do
	echo Copy to "${t@Q}:"
	skopeo copy --all --preserve-digests "oci-archive:${ar}:${tags[0]##*:}" "docker://${t}"
done
