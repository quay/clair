# Copyright 2024 clair authors
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

# Set the "DEBUG" variable to enable some debugging output for the Makefile
# itself.

.ONESHELL:
.SHELL = /usr/bin/bash
.SHELLFLAGS = -o pipefail -uec
.DELETE_ON_ERROR:
comma:=,
splice = $(subst $(eval ) ,$(comma),$1)
# See this file for all the variables that can be tuned by the environment.
include etc/config.mk
# Append shell patterns to this to hook the "clean" target.
rm_pat =

all:
	$(go) build ./cmd/...

# Use https://github.com/Mermade/widdershins to convert openapi.yaml to
# markdown. You'll need to have npx to run this.
Documentation/reference/api.md: openapi.yaml
	npx widdershins\
		--search false \
		--language_tabs 'python:Python' 'go:Golang' 'javascript:Javascript' \
		--summary $< \
		-o $@
# Intended to be checked-in, so not cleaned.

contrib/openshift/grafana/dashboards/dashboard-clair.configmap.yaml: \
	local-dev/grafana/provisioning/dashboards/dashboard.json \
	contrib/openshift/grafana/dashboard-clair.configmap.yaml.tpl
	name=$$(sed 's/[\&/]/\\&/g;s/$$/\\n/;s/^/    /' $< | tr -d '\n')
	sed "s/GRAFANA_MANIFEST/$$name/"\
		$(word 2,$^)\
		> $@
# Intended to be checked-in, so not cleaned.

include etc/container.mk
include etc/dev.mk
include etc/dist.mk
include etc/doc.mk

rm_flag := -rf
ifdef DEBUG
rm_flag += -v
endif
.PHONY: clean
clean:
	$(go) clean
	rm $(rm_flag) -- $(rm_pat)
