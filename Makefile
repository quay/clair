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
export PATH := /usr/local/bin:$(PATH)
export GOPATH := $(shell /bin/go env GOPATH)
export EC2_HOSTNAME := $(shell curl http://169.254.169.254/latest/meta-data/public-hostname)
export EC2_PUBLIC_IP := $(shell curl http://169.254.169.254/latest/meta-data/public-ipv4)
UNAME_KERNEL = $(shell uname -s)
UNAME_MACHINE = $(shell uname -m)

docker ?= docker
docker-compose ?= docker-compose
            
# Formats all imports to place local packages below out of tree packages.
.PHONY: goimports-local
goimports-local:
	/bin/go list -f '{{$$d := .Dir}}{{range .GoFiles}}{{printf "%s/%s\n" $$d .}}{{end}}' ./... | xargs sed -i'' '/import (/,/)/{ /^$$/d }'
	/bin/go list -f '{{.Dir}}' ./... | xargs goimports -local "$$(/bin/go list -m)" -w

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

vendor/modules.txt: go.mod
	/bin/go mod vendor

.PHONY: container-build
container-build:
ifneq ($(file < .git/HEAD),)
	$(docker) build "--build-arg=CLAIR_VERSION=$$(git describe --match 'v4.*')" -t clair-local:latest .
else
	$(docker) build -t clair-local:latest .
endif

DOCS_DIR ?= ../clair-doc
.PHONY: docs-build
docs-build:
	mdbook build
	rsync --recursive --delete-after --exclude 'v4.*' --exclude .git\
		./book/ $(DOCS_DIR)/

contrib/openshift/grafana/dashboards/dashboard-clair.configmap.yaml: local-dev/grafana/provisioning/dashboards/dashboard.json contrib/openshift/grafana/dashboard-clair.configmap.yaml.tpl
	sed "s/GRAFANA_MANIFEST/$$(sed -e 's/[\&/]/\\&/g' -e 's/$$/\\n/' -e 's/^/    /' $< | tr -d '\n')/" \
	$(word 2,$^) \
	> $@


# runs unit tests
.PHONY: unit
unit:
	/bin/go test -race ./...

.PHONY: quay-config
quay-config:
	curl -L "https://github.com/docker/compose/releases/download/1.28.6/docker-compose-$(UNAME_KERNEL)-$(UNAME_MACHINE)" -o /usr/local/bin/docker-compose
	chmod +x /usr/local/bin/docker-compose
	sed -i "s/{{ec2_instance_hostname}}/${EC2_HOSTNAME}/" local-dev/quay/config.yaml
	sed -i "s/{{ec2_instance_hostname}}/${EC2_HOSTNAME}/" docker-compose.yaml
	systemctl start docker
	systemctl enable docker

.PHONY: quay-server
quay-server: local-dev/clair/quay.yaml vendor
	rm -f /etc/systemd/system/quay.service
	cp local-dev/quay.service /etc/systemd/system/quay.service
	systemctl daemon-reload
	systemctl start quay
	systemctl enable quay
	@printf 'postgresql on port:\t%s\n' "$$($(docker-compose) port traefik 5432)"
	@printf 'quay on port:\t%s\n' "$$($(docker-compose) port traefik 8443)"

.PHONY: quay-nodejs-image
quay-nodejs-image:
	docker login --tls-verify=false -u="unicorn-games" -p="fishygame" ${EC2_HOSTNAME}
	docker pull node:14.21.2-alpine3.17
	docker tag node:14.21.2-alpine3.17 ${EC2_HOSTNAME}/unicorn-games/base-nodejs:14.21.2-alpine3.17
	docker push --tls-verify=false ${EC2_HOSTNAME}/unicorn-games/base-nodejs:14.21.2-alpine3.17