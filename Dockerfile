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

ARG GO_VERSION=1.17
FROM quay.io/projectquay/golang:${GO_VERSION} AS build
WORKDIR /build/
ADD . /build/
ARG CLAIR_VERSION=dev
RUN go build \
  -ldflags="-X main.Version=${CLAIR_VERSION}" \
  ./cmd/clair
RUN go build\
  ./cmd/clairctl

FROM registry.access.redhat.com/ubi8/ubi-minimal AS init
RUN microdnf install --disablerepo=* --enablerepo=ubi-8-baseos --enablerepo=ubi-8-appstream podman-catatonit

FROM registry.access.redhat.com/ubi8/ubi-minimal AS final
ENTRYPOINT ["/usr/local/bin/catatonit", "--", "/bin/clair"]
VOLUME /config
EXPOSE 6060
WORKDIR /run
ENV CLAIR_CONF=/config/config.yaml CLAIR_MODE=combo
ENV SSL_CERT_DIR="/etc/ssl/certs:/etc/pki/tls/certs:/var/run/certs"
USER nobody:nobody

COPY --from=init /usr/libexec/catatonit/catatonit /usr/local/bin/catatonit
COPY --from=build /build/clair /bin/clair
COPY --from=build /build/clairctl /bin/clairctl
