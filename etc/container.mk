# The following builds a command in the "buildctl" variable that expects a
# context in the shell variable "src" and for the make variable "@" (the
# target) to be present. NB these purposefully are not immediately expanded.
output_args = type=oci \"name=$(IMAGE_NAME)\" oci-mediatypes=true compression=estargz rewrite-timestamp=true dest=$@
buildctl = buildctl build --frontend dockerfile.v0
buildctl += --opt platform=$(call splice,$(foreach a,$(CONTAINER_PLATFORMS),linux/$a))
# DEBUG toggles on the "plain" buildkit output.
ifdef DEBUG
buildctl += --progress plain
endif
buildctl += --opt build-arg:BUILDKIT_MULTI_PLATFORM=1
buildctl += $(foreach v,$(buildkit_passthru),$(if $($v),--opt build-arg:$v=$($v),))
buildctl += --local context=$$src
buildctl += --local dockerfile=$$src
buildctl += --output $(call splice,$(output_args))
ifndef BUILDKIT_HOST
# Add a (hopefully) helpful warning that's printed on buildctl use.
buildctl += $(warning 'BUILDKIT_HOST' is not defined)
endif

# The "container" target builds a container using the current state of the tree.
.PHONY: container
container: clair.oci

# Clair.oci builds a container using the current state of the tree.
clair.oci: $(shell git ls-files -- ':*.go' ':go.mod' ':go.sum') Makefile Dockerfile
	src=.
	$(buildctl)
rm_pat += clair.oci

# Container-build creates a container using the current state of the tree and
# loads it into the container engine.
.PHONY: container-build
container-build: clair.oci
	$(docker) load <$<

# The "dist-container" target builds a container using a created dist archive.
.PHONY: dist-container
dist-container: clair-$(VERSION).oci

# Clair-%.oci builds a container using the state of the tree at the commit
# indicated by the pattern.
clair-%.oci: clair-%.tar.gz
	src=$$(mktemp -d)
	trap 'rm -rf $$src' EXIT
	tar -xzf $< -C $$src --strip-components=1
	$(buildctl)
rm_pat += clair-*.oci
