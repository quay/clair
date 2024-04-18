#!/bin/sh
set -e
: "${CLAIRCORE_BRANCH:=main}"

echo "::group::go version"
cd "$(git rev-parse --show-toplevel)"
go version
echo "::endgroup::"

test -d vendor && rm -rf vendor

echo "::group::Changes"
go mod edit \
	"-replace=github.com/quay/claircore=github.com/quay/claircore@${CLAIRCORE_BRANCH}"
go mod tidy
go mod download # Shouldn't be needed, but just to be safe...
git diff
echo "::endgroup::"

clair_version="$(git describe --tags --always --dirty --match 'v4.*')"
echo "::notice::Clair version: ${clair_version}"
echo "clair_version=${clair_version}" >> "$GITHUB_OUTPUT"
