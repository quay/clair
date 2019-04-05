#!/bin/bash
set -e
GOPATH="$(cd $(pwd -P)/../../../..; pwd -P)" go install ./cmd/clair
echo "Generated binary: $GOBIN/clair"
