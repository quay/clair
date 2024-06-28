# The "vendor" target aliases the actual file that controls the go vendor
# directory.
.PHONY: vendor
vendor: vendor/modules.txt

findpat := find . -name vendor -prune -o -name

# `Vendor/modules.txt` is the file that records vendored modules.
#
# It's touched on every run of `go mod vendor`, so should be a good proxy for
# the whole tree.
vendor/modules.txt: go.mod $(shell $(findpat) *.go -print)
	go mod vendor
rm_pat += vendor

# Formats all imports to place local packages below out of tree packages.
.PHONY: fmt
fmt:
	$(go) list -f '{{$$d := .Dir}}{{range .GoFiles}}{{printf "%s/%s\n" $$d .}}{{end}}' ./... |\
		xargs sed -i'' '/import (/,/)/{ /^$$/d }'
	$(go) list -f '{{.Dir}}' ./... |\
		xargs $(go) run $(goimports) -local $(shell $(go) list -m) -w

a := $(if $(testargs), $(testargs),)
.PHONY: check
check:
	$(findpat) go.mod -execdir $(go) test$(a) ./... \;

.PHONY: checkall
checkall:
	$(go) test$(a) $$( $(go) list -m all | awk '$$1~/github\.com\/quay\/clair/{print $$1"/..."}' )

# Start a local development environment.
#
# Each service runs in its own container to test service-to-service
# communication. Local dev configuration can be found in
# "/local-dev/clair/config.yaml"
.PHONY: local-dev
local-dev: vendor
	$(docker-compose) up -d
	printf 'postgresql on port:\t%s\n' "$$($(docker-compose) port traefik 5432)"

# Targets for docker-compose profiles.
#
# TODO(hank) This should build the list of profiles from the
# docker-compose.yaml file. Would require parsing yaml, though.
compose_profiles := quay notifier debug
compose_targets := $(addprefix local-dev-,$(compose_profiles))
compose_clair_configs := $(addprefix local-dev/clair/,$(addsuffix .yaml,$(compose_profiles)))
.PHONY: $(compose_targets)
local-dev-%: local-dev/clair/$*.yaml vendor
	CLAIR_CONFIG=$(<F) $(docker-compose) --profile $* up -d
	printf 'postgresql on port:\t%s\n' "$$($(docker-compose) port traefik 5432)"
	printf 'quay on port:\t%s\n' "$$($(docker-compose) port traefik 8443 || echo N/A)"

# Some light metaprogramming to construct overridable recipes for per-profile configs.
dev-config = $(let in out,$1,cp $(in) $(out))
dev-config-quay = $(let in out,$1,\
	sed '/target:/s,webhook-target/,clair-quay:8443/secscan/notification,' <$(in) >$(out))
# The following uses the "call" on the contents of "dev-config-${profile}" if
# defined, falling back to "dev-config".
$(compose_clair_configs): local-dev/clair/%.yaml: local-dev/clair/config.yaml
	$(call $(if $(dev-config-$*),dev-config-$*,dev-config),$< $@)
rm_pat += local-dev/clair/{$(call splice,$(compose_profiles))}.yaml
