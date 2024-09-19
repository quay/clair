# syntax=docker.io/docker/dockerfile:1.7

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

ARG GOTOOLCHAIN=local
ARG GO_VERSION=1.22
FROM --platform=$BUILDPLATFORM quay.io/projectquay/golang:${GO_VERSION} AS build
WORKDIR /build
RUN --mount=type=cache,target=/root/.cache/go-build \
	--mount=type=cache,target=/go/pkg/mod \
	--mount=type=bind,source=go.mod,target=go.mod \
	--mount=type=bind,source=go.sum,target=go.sum \
	go mod download

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG CLAIR_VERSION=""
# This script needs to use `go build` instead of `go install` to cross-compile.
RUN --mount=type=bind,target=. \
	--mount=type=cache,target=/root/.cache/go-build \
	--mount=type=cache,target=/go/pkg/mod \
	--network=none \
	<<.
set -e
export GOOS="$TARGETOS" GOARCH="$TARGETARCH" GOBIN=/out/bin
if [ -n "$TARGETVARIANT" ]; then
	case "$TARGETARCH" in
	amd64)  export GOAMD64="$TARGETVARIANT" ;;
	ppc64*) export GOPPC64="$TARGETVARIANT" ;;
	esac
fi
if [ -n "${CLAIR_VERSION}" ]; then
	vstr="${CLAIR_VERSION} (user)"
	cat <<msg >&2
Setting reported version to "${vstr}".

This hook into the go build process is not needed if building using a prepared
source archive and will go away in the future.

Please open an issue if this would prevent a desired use-case.
msg
	varg=" -X 'github.com/quay/clair/v4/cmd.Version=${vstr}'"
fi
install -d "${GOBIN}"
go build \
	-ldflags="-s -w$varg" -trimpath \
	-o "${GOBIN}" \
	./cmd/...
.

FROM scratch AS ctl
COPY --from=build /out/bin/clairctl* /

FROM registry.access.redhat.com/ubi8/ubi-minimal AS final
ENTRYPOINT ["/usr/bin/clair"]
VOLUME /config
EXPOSE 6060
ENV CLAIR_CONF=/config/config.yaml\
	CLAIR_MODE=combo\
	SSL_CERT_DIR="/etc/ssl/certs:/etc/pki/tls/certs:/var/run/certs"
USER nobody:nobody
# The WORKDIR command creates an empty layer, there's nothing we can do.
WORKDIR /run
COPY --from=build /out/bin/* /usr/bin/
