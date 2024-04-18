#!/bin/sh
set -e
: "${CLAIRCORE_BRANCH:=main}"
cd "$(git rev-parse --show-toplevel)"
test -d vendor && rm -rf vendor

echo "::group::Edits"
go mod edit \
	"-replace=github.com/quay/claircore=github.com/quay/claircore@${CLAIRCORE_BRANCH}"
go mod tidy
go mod download # Shouldn't be needed, but just to be safe...
echo "::endgroup::"

clair_version="$(git describe --tags --always --dirty --match 'v4.*')"
echo "clair_version=${clair_version}" >> "$GITHUB_OUTPUT"

cat <<. >>"$GITHUB_STEP_SUMMARY"
### Changes

- **Go version:** $(go version)
- **Clair version:** ${clair_version}
.
{
	echo '```patch'
	git diff
	echo '```' 
} >>"$GITHUB_STEP_SUMMARY"
