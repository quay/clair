#!/bin/sh
# Bundle the go-json-experiment package(s)
set -e
find . -name bundle.go -delete

upstream='github.com/go-json-experiment'
root="$(go list -m)/internal"
pkglist='json/internal/jsonflags json/internal/jsonopts json/internal/jsonwire json/internal json/jsontext json'
for pkg in $pkglist; do
	maparg="${maparg}${maparg+ }-import=${upstream}/${pkg}=${root}/${pkg}"
done

for pkg in $pkglist; do
	dir=$(echo "$pkg" | sed 's,^json,.,')
	mkdir -p "$dir"
	echo "package $(basename "$pkg")" > "${dir}/temp.go"
	eval "go run golang.org/x/tools/cmd/bundle -prefix '' $maparg -dst ${root}/${pkg} ${upstream}/${pkg} > _bundle.go"
	mv _bundle.go "${dir}/bundle.go"
done

find . -name temp.go -delete
go mod tidy
