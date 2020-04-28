# Copyright 2019 clair authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

COMMIT = $(shell git describe --tag --always --dirty)

UNIT_TEST_PACKAGES = $(shell go list ./... | grep -v 'database/')
DB_TEST_PACKAGES = $(shell go list ./... | grep 'database/')

CLAIR_TEST_PGSQL ?= postgres@127.0.0.1:5432
GO111MODULE ?= on
export GO111MODULE

.PHONY: build
build:
	go build -v -ldflags "-X github.com/quay/clair/v3/pkg/version.Version=$(COMMIT)" ./cmd/clair

.PHONY: unit-test
unit-test:
	go test $(UNIT_TEST_PACKAGES)

.PHONY: db-test
db-test:
	# The following executes integration tests with a live, but empty database.
	@echo 'CLAIR_TEST_PGSQL: $(CLAIR_TEST_PGSQL)'
	go test $(DB_TEST_PACKAGES)

.PHONY: deploy-local
deploy-local:
	# This make target is designed to be ran idempotently.
	# Each run deploys the latest code in the repository requires kubernetes.
	# Both minikube and docker desktop is supported.
	./local-dev/build.sh
	-helm dependency update ./local-dev/helm/clair-pg
	-helm upgrade --install clair-pg ./local-dev/helm/clair-pg
	helm upgrade --install clair ./local-dev/helm/clair

.PHONY: teardown-local
teardown-local:
	# This target tears down the environment deployed by deploy-local.
	-helm delete --purge clair
	-helm delete --purge clair-pg

.PHONY: lint-proto
lint-proto:
	clang-format -i api/v3/clairpb/clair.proto


.PHONY: gen-drone-config
gen-drone-config:
	drone jsonnet --stream .drone.jsonnet
