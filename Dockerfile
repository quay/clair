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

FROM golang:1.14-alpine AS build
RUN apk add --no-cache build-base
WORKDIR /build/
ADD . /build/
ARG CLAIR_VERSION=dev
RUN go build \
	-mod=vendor \
	-ldflags="-X main.Version=${CLAIR_VERSION}" \
	./cmd/clair

FROM alpine:3.10 AS final
RUN apk add --no-cache tar rpm ca-certificates dumb-init
# change ownership of ssl directory to allow custom cert in OpenShift
RUN chgrp -R 0 /etc/ssl/certs && \
    chmod -R g=u /etc/ssl/certs
ENTRYPOINT ["/usr/bin/dumb-init", "--", "/bin/clair"]
VOLUME /config
EXPOSE 6060
WORKDIR /run
ENV CLAIR_CONF=/config/config.yaml CLAIR_MODE=combo

COPY --from=build /build/clair /bin/clair
