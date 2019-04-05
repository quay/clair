REPOTAG?=clair-local-test:master
CLAIR_TEST_PGSQL?=
export CLAIR_TEST_PGSQL

build:
    docker build -t ${REPOTAG} .

test:
	scripts/test.sh

travis_test:
	scripts/test.sh

install:
	scripts/local_install.sh
