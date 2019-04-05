#!/bin/bash
set -e

export TESTBIN="$(pwd -P)/.testbin/"
export PATH=$PATH:$TESTBIN
export GOPATH="$(cd $(pwd -P)/../../../..; pwd -P)"
export CLAIR_TEST_PGSQL=$CLAIR_TEST_PGSQL
export CLAIR_DEFAULT_DB_PORT=8491

echo "Setting test environment"

if [ ! -e $TESTBIN/prototool ]; then
    echo "Retrieving prototool"
    mkdir $TESTBIN
    curl -o $TESTBIN/prototool -sSL https://github.com/uber/prototool/releases/download/v0.1.0/prototool-$(uname -s)-$(uname -m)
    chmod +x $TESTBIN/prototool
fi

if [ -z "$CLAIR_TEST_PGSQL" ]; then
    export CLAIR_TEST_PGSQL="postgres://127.0.0.1:$CLAIR_DEFAULT_DB_PORT"
    echo "Setting up Clair Test DB at $CLAIR_TEST_PGSQL"
    docker run --name clair_test_pgsql_db -d -e POSTGRES_PASSWORD="" -p $CLAIR_DEFAULT_DB_PORT:5432 postgres:9.6
fi

echo "Linting"
diff -u <(echo -n) <(gofmt -l -s $(go list -f '{{.Dir}}') | grep -v '/vendor/')

PATH=$TESTBIN prototool format -d api/v3/clairpb/clair.proto
PATH=$TESTBIN prototool lint api/v3/clairpb/clair.proto

echo "Testing"
go test $(glide novendor | grep -v contrib)

echo "Cleaning"
docker rm -f clair_test_pgsql_db