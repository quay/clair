#!/usr/bin/bash
set -euo pipefail

splice() { local IFS="$1"; shift; echo "$*"; }

while getopts nxz name; do
	case "$name" in
	x) set -x ;;
	n) dryrun=1 ;;
	z) declare -g login_done ;;
	?)
		printf "Usage: %s: [-nxz]\n" "$0"
		exit 2
		;;
	esac
done

: "${REGISTRY:=quay.io}"
: "${NAMESPACE:=app-sre}"
: "${REPOSITORY:=clair}"
: "${IMAGE:=$(splice / "$REGISTRY" "$NAMESPACE" "$REPOSITORY")}"
: "${BUILDKIT_VERSION:=0.15.2}"
: "${BUILDKIT_IMAGE:=$(splice / "$REGISTRY" "$NAMESPACE" "buildkit:latest")}"
: "${CONTAINER_ENGINE:=$(command -v podman 2>/dev/null || command -v docker 2>/dev/null)}"
: "${cidfile:=buildkit.cid}"
GIT_HASH="$(git rev-parse --short=7 HEAD)"
tags=("${IMAGE}:latest" "${IMAGE}:${GIT_HASH}")
trap 'rm -rf clair-v*.{tar*,oci} ' ERR
export GOTOOLCHAIN=auto # have any local invocations of go use the correct version magically

patch_source() {
	in=$1
	want=$(git ls-files ':**Dockerfile' | wc -l)
	if [[ $(tar tf "$in" '*/Dockerfile' | wc -l) -gt $want ]]; then
		echo already patched >&2
		return
	fi
	if [[ "${BUILDKIT_IMAGE%%/*}" = docker.io ]]; then
		echo guessing no patching needed, based on BUILDKIT_IMAGE "(${BUILDKIT_IMAGE})" >&2
		return
	fi

	( # Subshell to set a cleanup trap.
	tmp=$(mktemp -d)
	trap 'rm -r "$tmp"' EXIT
	gunzip "$in"
	in=${in%.gz}

	# remove the syntax line -- should be OK as long as we're not using features
	# beyond the buildkit-shipped version.
	for file in $(tar tf "$in" '*/Dockerfile'); do
		tar -xOf "$in" "$file" |
			sed '/# syntax/d' >"${tmp}/Dockerfile"
		tar -rf "$in" --transform "s,.*,${file}," "${tmp}/Dockerfile"
	done
	gzip -n -q -f "$in"
	)
}

registry_login(){
	[[ -v login_done ]] && return
	f="$(mktemp -d)/auth.json"
	export REGISTRY_AUTH_FILE="$f" DOCKER_CONFIG="${f%/*}"
	${CONTAINER_ENGINE} login -u="${QUAY_USER}" -p="${QUAY_TOKEN}" "${REGISTRY}"
	declare -g login_done
}

if [[ -d bin ]]; then
	PATH=$(realpath bin):${PATH}
fi
if ! command -v buildctl >/dev/null 2>&1; then
	echo Fetching buildctl:
	mkdir -p bin
	PATH=$(realpath bin):${PATH}
	curl -sSfL "https://github.com/moby/buildkit/releases/download/v${BUILDKIT_VERSION}/buildkit-v${BUILDKIT_VERSION}.linux-amd64.tar.gz" |
		tar -xzC bin --strip-components=1 bin/buildctl
	command -V buildctl
	buildctl --version
fi

cleanup() {
	todo=( ${login_done:+${REGISTRY_AUTH_FILE}} )
	if [[ -f "${cidfile}" ]]; then
		echo Stopping buildkitd container:
		[[ -o x ]] && ${CONTAINER_ENGINE} logs "$(cat "${cidfile}")"
		${CONTAINER_ENGINE} stop --cidfile "${cidfile}" || echo Failed to stop buildkit container >&2
		todo+=( "${cidfile}" )
	fi
	[[ "${#todo[@]}" -ne 0 ]] && rm -rf "${todo[@]}"
}

trap 'cleanup' EXIT
# Unconditionally log in if we have credentials because AppSRE CI can't be
# bothered to clear them between Jenkins jobs.
if [[ -n "${QUAY_USER-}" && -n "${QUAY_TOKEN-}" ]]; then
	registry_login
fi
if [[ ! -v BUILDKIT_HOST ]]; then
	echo Starting buildkitd container:
	[[ -x o ]] && skopeo list-tags "docker://${BUILDKIT_IMAGE%:*}"
	${CONTAINER_ENGINE} run \
		--cidfile "${cidfile}" \
		--detach \
		--privileged \
		--rm \
		"${BUILDKIT_IMAGE}"
	BUILDKIT_HOST="$(basename "${CONTAINER_ENGINE}")-container://$(cat "$cidfile")"
	export BUILDKIT_HOST
fi

echo Exporting source:
make dist

echo Applying self-inflicted wound:
if [[ $(find . -maxdepth 1 -type f -name 'clair-v*.tar*' | wc -l) -ne 1 ]]; then
	echo found multiple dist tarballs, exiting: >&2
	ls clair-v*.tar* >&2
	exit 99
fi
patch_source clair-v*.tar.gz

echo Building container:
make "IMAGE_NAME=$(splice , "${tags[@]}")" dist-container

# Make repeated runs work more-or-less correctly.
touch -m -t 197001010000 clair-v*.{tar.gz,oci}

[[ -n "${dryrun-}" ]] && exit 0

: "${QUAY_USER:?Missing QUAY_USER variable.}"
: "${QUAY_TOKEN:?Missing QUAY_TOKEN variable.}"
registry_login

ar=$(echo clair-v4.*.oci)
for t in "${tags[@]}"; do
	echo Copy to "${t@Q}:"
	skopeo copy --all --preserve-digests "oci-archive:${ar}:${tags[0]##*:}" "docker://${t}"
done
