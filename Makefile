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

# Formats all imports to place local packages below out of tree packages.
.PHONY: goimports-local
goimports-local:
	go list -f '{{$$d := .Dir}}{{range .GoFiles}}{{printf "%s/%s\n" $$d .}}{{end}}' ./... | xargs sed -i'' '/import (/,/)/{ /^$$/d }'
	go list -f '{{.Dir}}' ./... | xargs goimports -local "$$(go list -m)" -w

# Use https://github.com/Mermade/widdershins to convert openapi.yaml to
# markdown. You'll need to have npx to run this.
Documentation/reference/api.md: openapi.yaml
	npx widdershins --search false --language_tabs 'python:Python' 'go:Golang' 'javascript:Javascript' --summary $< -o $@

local-dev/clair/quay.yaml: local-dev/clair/config.yaml
	sed '/target:/s,webhook-target/,clair-quay:8443/secscan/notification,' <$< >$@

# Start a local development environment.
#
# Each service runs in its own container to test service-to-service
# communication.  Local dev configuration can be found in
# "./local-dev/clair/config.yaml"
.PHONY: local-dev
local-dev: vendor
	$(docker-compose) up -d
	@printf 'postgresql on port:\t%s\n' "$$($(docker-compose) port traefik 5432)"

compose_profiles = $(patsubst %,local-dev-%,quay notifier debug)
.PHONY: $(compose_profiles)
local-dev-%: vendor
	$(docker-compose) --profile $* up -d
	@printf 'postgresql on port:\t%s\n' "$$($(docker-compose) port traefik 5432)"

local-dev-quay: local-dev/clair/quay.yaml vendor
	CLAIR_CONFIG=$(<F) $(docker-compose) --profile quay up -d
	@printf 'postgresql on port:\t%s\n' "$$($(docker-compose) port traefik 5432)"
	@printf 'quay on port:\t%s\n' "$$($(docker-compose) port traefik 8443)"

.PHONY: vendor
vendor: vendor/modules.txt

vendor/modules.txt: go.mod $(shell find . -name vendor -prune -o -name *.go -print)
	go mod vendor

.PHONY: container-build
container-build:
	$(docker) build $(if $(findstring podman,$(docker)),--security-opt=label=disable ,)-t clair-local:latest .

contrib/openshift/grafana/dashboards/dashboard-clair.configmap.yaml: local-dev/grafana/provisioning/dashboards/dashboard.json contrib/openshift/grafana/dashboard-clair.configmap.yaml.tpl
	sed "s/GRAFANA_MANIFEST/$$(sed -e 's/[\&/]/\\&/g' -e 's/$$/\\n/' -e 's/^/    /' $< | tr -d '\n')/" \
	$(word 2,$^) \
	> $@
