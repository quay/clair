#!/bin/bash

set -euo pipefail

install(){
    echo "GOPATH=$(cd $(pwd -P)/../../../..; pwd -P)"
    GOPATH="$(cd $(pwd -P)/../../../..; pwd -P)" go install ./cmd/clair
    echo "install: Installed to $GOBIN/clair"
}

case "$1" in
    build)
        build $2
        ;;

    install)
        install
        ;;

    test)
        lint
        test $2
        ;;

    *)
        echo "Usage: $0 {build <tag name> | install | test <test postgres db link>}"
        exit 1
        ;;
esac
