#!/bin/sh
set -e
: "${CLAIRCORE_BRANCH:=main}"
: "${GO_VERSION:=1.20}"
test "${#GO_VERSION}" -gt 4 && GO_VERSION=${GO_VERSION%.*}

cd "$(git rev-parse --show-toplevel)"
echo '#' "$(go version)"
go mod edit "-go=${GO_VERSION}"\
	"-replace=github.com/quay/claircore=github.com/quay/claircore@${CLAIRCORE_BRANCH}"
git diff
test -d vendor && rm -rf vendor
go mod tidy
go mod vendor
echo "clair_version=$(git describe --tags --always --dirty --match 'v4.*')" >> "$GITHUB_OUTPUT"
