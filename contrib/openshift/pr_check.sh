#!/usr/bin/bash
set -euo pipefail
[ -n "${DEBUG-}" ] && set -x

# This should be run from the repo root, but enforce that:
pushd "$(git rev-parse --show-toplevel)"
./contrib/openshift/build_and_deploy.sh "-n${-//[^x]}${SKIP_LOGIN:+z}"
popd

# If anything specific for the quay.io Clair instance needs to happen, add that here.
