# Copyright 2017 clair authors
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

ARG GO_VERSION=1.21
FROM quay.io/projectquay/golang:${GO_VERSION} AS build
WORKDIR /build
RUN --mount=type=cache,target=/root/.cache/go-build \
	--mount=type=cache,target=/go/pkg/mod \
	--mount=type=bind,source=go.mod,target=go.mod \
	--mount=type=bind,source=go.sum,target=go.sum \
	go mod download
COPY . .
ARG CLAIR_VERSION=""
RUN --mount=type=cache,target=/root/.cache/go-build \
	--mount=type=cache,target=/go/pkg/mod \
	go build \
	-ldflags="-s -w$(test -n "$CLAIR_VERSION" && printf " -X 'github.com/quay/clair/v4/cmd.Version=%s (user)'" "${CLAIR_VERSION}")" \
	-o . \
	-trimpath \
	./cmd/...

FROM registry.access.redhat.com/ubi8/ubi-minimal AS final
ENTRYPOINT ["/bin/clair"]
VOLUME /config
EXPOSE 6060
WORKDIR /run
ENV CLAIR_CONF=/config/config.yaml CLAIR_MODE=combo
ENV SSL_CERT_DIR="/etc/ssl/certs:/etc/pki/tls/certs:/var/run/certs"
USER nobody:nobody

COPY --from=build /build/clair /bin/clair
COPY --from=build /build/clairctl /bin/clairctl
