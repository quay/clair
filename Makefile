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
docker ?= docker
docker-compose ?= docker-compose

# formats all imports to place local modules
# below out of tree modules
.PHONY: goimports-local
goimports-local:
	go list -f '{{$$d := .Dir}}{{range .GoFiles}}{{printf "%s/%s\n" $$d .}}{{end}}' ./... | xargs sed -i'' '/import (/,/)/{ /^$$/d }'
	go list -f '{{.Dir}}' ./... | xargs goimports -local "$(go list -m)" -w

# https://github.com/Mermade/widdershins used to convert openapi.yaml to markdown
# you'll need to have npx to run this gen.
.PHONY: gen-api-reference
gen-api-reference:
	npx widdershins --search false --language_tabs 'python:Python' 'go:Golang' 'javascript:JavaScript' --summary ./openapi.yaml -o ./Documentation/reference/api.md

# start a local development environment. 
# each services runs in it's own container to test service->service communication.
#
# local dev configuration can be found in "./local-dev/clair/config.yaml"
.PHONY: local-dev-up
local-dev-up: vendor
	$(docker-compose) up -d traefik
	$(docker-compose) up -d jaeger
	$(docker-compose) up -d prometheus
	$(docker-compose) up -d grafana
	$(docker-compose) up -d rabbitmq
	$(docker-compose) up -d activemq
	$(docker-compose) up -d clair-db
	$(docker) exec -it clair-db bash -c 'while ! pg_isready; do echo "waiting for postgres"; sleep 2; done'
	$(docker-compose) up -d pgadmin
	$(docker-compose) up -d indexer
	$(docker-compose) up -d matcher
	$(docker-compose) up -d notifier
	$(docker-compose) up -d swagger-ui

.PHONY: local-dev-up-with-quay
local-dev-up-with-quay: vendor
	## clair ##
	$(docker-compose) up -d traefik
	$(docker-compose) up -d jaeger
	$(docker-compose) up -d prometheus
	$(docker-compose) up -d grafana
	$(docker-compose) up -d rabbitmq
	$(docker-compose) up -d activemq
	$(docker-compose) up -d clair-db
	$(docker) exec -it clair-db bash -c 'while ! pg_isready; do echo "waiting for clair postgres"; sleep 2; done'
	$(docker-compose) up -d pgadmin
	$(docker-compose) up -d indexer-quay
	$(docker-compose) up -d matcher
	$(docker-compose) up -d notifier
	$(docker-compose) up -d swagger-ui
	## quay ##
	$(docker-compose) up -d redis
	$(docker-compose) up -d quay-db
	$(docker) exec -it quay-db bash -c 'while ! pg_isready; do echo "waiting for quay postgres"; sleep 2; done'
	$(docker) exec -it quay-db /bin/bash -c 'echo "CREATE EXTENSION IF NOT EXISTS pg_trgm" | psql -d quay -U quay'
	$(docker-compose) up -d quay

.PHONY: local-dev-restart-quay
local-dev-restart-quay: 
	$(docker-compose) up -d --force-recreate quay

# starts a local dev environment for testing notifier
# the notifier will create a notification on very notifier.poll_interval value in the local dev configuration.
# 
# the notifier will deliver the notification to the configured deliverer in the local dev configuration. 
# the default deliverer is rabbitmq/amqp
#
# local dev configuration can be found in "./local-dev/clair/config.yaml"
.PHONY: local-dev-notifier-test
local-dev-notifier-test: vendor
	$(docker-compose) up -d traefik
	$(docker-compose) up -d jaeger
	$(docker-compose) up -d prometheus
	$(docker-compose) up -d rabbitmq
	$(docker-compose) up -d activemq
	$(docker-compose) up -d clair-db
	$(docker) exec -it clair-db bash -c 'while ! pg_isready; do echo "waiting for postgres"; sleep 2; done'
	$(docker-compose) up -d notifier-test-mode
	$(docker-compose) up -d swagger-ui

.PHONY: local-dev-notifier-test-restart
local-dev-notifier-test-restart: vendor
	$(docker-compose) up -d --force-recreate notifier-test-mode

vendor: vendor/modules.txt

vendor/modules.txt: go.mod
	go mod vendor

# tear down the entire local development environment
.PHONY: local-dev-down
local-dev-down:
	$(docker-compose) down

# restart the local development database, clearing all it's contents
# often a service should be restarted as well to run migrations on the now schemaless database.
.PHONY: local-dev-db-restart
local-dev-db-restart:
	$(docker) kill clair-db && $(docker) rm clair-db
	$(docker-compose) up -d --force-recreate clair-db

# restart the local development indexer, any local code changes will take effect
.PHONY: local-dev-indexer-restart
local-dev-indexer-restart:
	$(docker-compose) up -d --force-recreate indexer

# restart the local development matcher, any local code changes will take effect
.PHONY: local-dev-matcher-restart
local-dev-matcher-restart:
	$(docker-compose) up -d --force-recreate matcher

# restart the local development notifier, any local code changes will take effect
.PHONY: local-dev-notifier-restart
local-dev-notifier-restart:
	$(docker-compose) up -d --force-recreate notifier

# restart all clair instances
.PHONY: local-dev-clair-restart
local-dev-clair-restart:
	$(docker-compose) up -d --force-recreate indexer
	$(docker-compose) up -d --force-recreate matcher
	$(docker-compose) up -d --force-recreate notifier

# restart the local development rabbitmq
.PHONY: local-dev-rabbitmq-restart
local-dev-rabbitmq-restart:
	$(docker-compose) up -d --force-recreate rabbitmq

# restart the local development swagger-ui, any local code changes will take effect
.PHONY: local-dev-swagger-ui-restart
local-dev-swagger-ui-restart:
	$(docker-compose) up -d --force-recreate swagger-ui
	 
# restart the local development swagger-ui, any local code changes will take effect
.PHONY: local-dev-traefik-restart
local-dev-traefik-restart:
	$(docker-compose) up -d --force-recreate traefik

.PHONY: container-build
container-build:
	$(docker) build -t clair-local:latest .

DOCS_DIR ?= ../clair-doc
.PHONY: docs-build
docs-build:
	mdbook build
	rsync --recursive --delete-after --exclude 'v4.*' --exclude .git\
		./book/ $(DOCS_DIR)/

# runs unit tests
.PHONY: unit
unit:
	go test -race ./...
