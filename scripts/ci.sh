#!/bin/bash

set -euo pipefail

IMAGE='clair-ci:ci-0nQbHnN'

build() {
    echo "build: Building Clair Image ${IMAGE}"
    docker build -t "${IMAGE}" .
    echo "build: Finished"
}

lint(){
    diff -u <(echo -n) <(gofmt -l -s $(go list -f '{{.Dir}}') | grep -v '/vendor/')
    prototool format -d api/v3/clairpb/clair.proto
    prototool lint api/v3/clairpb/clair.proto
}

unit(){
    go test $(glide novendor | grep -v contrib)
}

case "$1" in
    build)
        build_image
        ;;

    lint)
        lint
        ;;

    unit)
        unit
        ;;

    *)
        echo "Usage: $0 {build|unit}"
        exit 1
        ;;
esac
