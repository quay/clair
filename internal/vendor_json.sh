#!/usr/bin/env bash
# This is a port of the migrate.sh from go-json-experiment.
set -euo pipefail

GOROOT=$(go env GOROOT)
JSONROOT=$(realpath json)
echo copying from "$GOROOT" '('$(go version)')'

#rm -r $JSONROOT ||:
#mkdir -p $JSONROOT
rsync \
	--recursive --verbose --delete \
	--exclude={**/testdata,**/jsontest,*_test.go} \
	$GOROOT/src/encoding/json/{v2/,internal,jsontext} \
	$JSONROOT/

sedscript=$(mktemp --tmpdir migrate_jsonv2.XXXXXX)
cat <<'.' >$sedscript
s/go:build goexperiment.jsonv2$/go:build !goexperiment.jsonv2 || !go1.25/;
s|"encoding/json/v2"|"github.com/quay/clair/v4/internal/json"|;
s|"encoding/json/internal"|"github.com/quay/clair/v4/internal/json/internal"|;
s|"encoding/json/internal/jsonflags"|"github.com/quay/clair/v4/internal/json/internal/jsonflags"|;
s|"encoding/json/internal/jsonopts"|"github.com/quay/clair/v4/internal/json/internal/jsonopts"|;
s|"encoding/json/internal/jsonwire"|"github.com/quay/clair/v4/internal/json/internal/jsonwire"|;
s|"encoding/json/jsontext"|"github.com/quay/clair/v4/internal/json/jsontext"|;
.
trap "rm -f '$sedscript'" EXIT

find "$JSONROOT" \
	-type f -name '*.go' \
	-exec sed -f "$sedscript" -i '{}' \; \
	-exec goimports -w '{}' \+
find "$JSONROOT" \
	-type f -name 'doc.go' \
	-exec sed -i '/This package .* is experimental/,+4d' '{}' \+

go run alias_gen.go "encoding/json/v2"       $JSONROOT
go run alias_gen.go "encoding/json/jsontext" $JSONROOT/jsontext
go test -run none $JSONROOT/...
