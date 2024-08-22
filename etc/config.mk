# `docker` and `docker-compose` control the commands invoked for a container
# engine and a "compose file" handler, respectively.
docker ?= $(notdir $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null))
ifndef docker
$(error 'docker' must not be defined as empty [checked for: podman, docker])
endif
docker-compose ?= $(notdir $(shell command -v docker-compose 2>/dev/null))
ifndef docker-compose
$(error 'docker-compose' must not be defined as empty [checked for: docker-compose])
endif

# `Skopeo` controls the specific skopeo command invoked when needed.
skopeo ?= $(notdir $(shell command -v skopeo 2>/dev/null))
ifndef skopeo
$(error 'skopeo' must not be defined as empty [checked for: skopeo])
endif

# `go` controls the specific go command invoked when needed.
go ?= $(notdir $(shell command -v go 2>/dev/null))
ifndef go
$(error 'go' must not be defined as empty [checked for: go])
endif

# The package used (via `go run`) to format go files.
goimports ?= golang.org/x/tools/cmd/goimports@latest

# `Buildctl` controls the specific buildctl command invoked when needed.
buildctl ?= $(notdir $(shell command -v buildctl 2>/dev/null))
ifndef buildctl
buildctl = $(go) run github.com/moby/buildkit/cmd/buildctl@latest
endif

# This is the command invoked when `git archive` is needed.
# The config option forces consistent line endings.
git_archive = git -c core.autocrlf=false archive

# These are arguments added to `go test` invocations.
testargs =

# VERSION is the version used when guessing at the current version to be used
# in dist artifacts.
#
# This should be able to be interpreted according to gitrevisions(7) and a
# semver. The default does this by processing `git describe` output.
VERSION ?= $(shell git describe --match 'v*' --long | sed 's/\(.\+\)-\([0-9]\+-g[a-f0-9]\)/\1+\2/')
ifndef VERSION
$(error 'VERSION' must not be defined as empty)
endif

# `IMAGE_NAME` is the names(s) used for the `buildctl` invocations.
# Can be provided as a comma-separated list for multiple names.
IMAGE_NAME ?= localhost/clair:latest
ifndef IMAGE_NAME
$(error 'IMAGE_NAME' not defined, need at least one comma-separated value)
endif

# `CONTAINER_PLATFORMS` controls the architectures (in OCI notation) of the
# platforms to build container images for. The OS component is always "linux."
CONTAINER_PLATFORMS ?= amd64 arm64 ppc64le s390x
ifndef CONTAINER_PLATFORMS
$(error 'CONTAINER_PLATFORMS' not defined, need at least one space-separated value)
endif

# The following environment variables are passed as build arguments to the buildctl command, if present:
#
# - `CLAIR_VERSION`
# - `GO_VERSION`
# - `GOTOOLCHAIN`
# - `SOURCE_DATE_EPOCH`
#
# The first three are used in the Dockerfile.
# The last is an argument to the dockerfile fronend. See also:
# https://github.com/moby/buildkit/blob/master/frontend/dockerfile/docs/reference.md#buildkit-built-in-build-args
buildkit_passthru := CLAIR_VERSION GO_VERSION GOTOOLCHAIN SOURCE_DATE_EPOCH

# Any overrides can be put here:
-include etc/config.local.mk

ifdef DEBUG
$(let vars,\
	docker docker-compose go goimports testargs VERSION IMAGE_NAME CONTAINER_PLATFORMS $(buildkit_passthru),\
	$(foreach var,$(vars), $(info DEBUG: $(var): $($(var))))\
)
endif
