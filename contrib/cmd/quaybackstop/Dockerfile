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

# This Dockerfile expects the context to be the root of the repo, e.g.:
#     go run github.com/moby/buildkit/cmd/buildctl@latest build \
#     --frontend dockerfile.v0 \
#     --local context=. --local dockerfile=contrib/cmd/quaybackstop

ARG GOTOOLCHAIN=local
ARG GO_VERSION=1.23
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
RUN --mount=type=bind,target=. \
	--mount=type=cache,target=/root/.cache/go-build \
	--mount=type=cache,target=/go/pkg/mod \
	--network=none \
	<<.
set -e
export GOOS="$TARGETOS" GOARCH="$TARGETARCH" GOBIN=/out/bin CGO_ENABLED=0
if [ -n "$TARGETVARIANT" ]; then
	case "$TARGETARCH" in
	amd64)  export GOAMD64="$TARGETVARIANT" ;;
	ppc64*) export GOPPC64="$TARGETVARIANT" ;;
	esac
fi
install -d "${GOBIN}"
go build -ldflags="-s -w" -trimpath -o "${GOBIN}" ./contrib/cmd/quaybackstop
.

FROM gcr.io/distroless/static:nonroot AS final
COPY --from=build /out/bin/quaybackstop /
WORKDIR /run
USER 65532:65532
ENTRYPOINT ["/quaybackstop"]
