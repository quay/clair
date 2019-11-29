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

# start a local development environment. 
# each services runs in it's own container to test service->service communication.
.PHONY: local-dev-up
local-dev-up:
	$(docker-compose) up -d clair-db
	$(docker) exec -it clair_clair-db_1 bash -c 'while ! pg_isready; do echo "waiting for postgres"; sleep 2; done'
	go mod vendor
	$(docker-compose) up -d indexer
	$(docker-compose) up -d matcher
	$(docker-compose) up -d swagger-ui

# tear down the entire local development environment
.PHONY: local-dev-down
local-dev-down:
	$(docker-compose) down

# restart the local development database, clearing all it's contents
# often a service should be restarted as well to run migrations on the now schemaless database.
.PHONY: local-dev-db-restart
local-dev-db-restart:
	$(docker-compose) up -d --force-recreate clair-db

# restart the local development indexer, any local code changes will take effect
.PHONY: local-dev-indexer-restart
local-dev-indexer-restart:
	$(docker-compose) up -d --force-recreate indexer

# restart the local development matcher, any local code changes will take effect
.PHONY: local-dev-matcher-restart
local-dev-matcher-restart:
	$(docker-compose) up -d --force-recreate matcher

# restart the local development swagger-ui, any local code changes will take effect
.PHONY: local-dev-swagger-ui-restart
local-dev-swagger-ui-restart:
	$(docker-compose) up -d --force-recreate swagger-ui
