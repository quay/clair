#!/usr/bin/env bash

# Copyright 2018 clair authors
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

set -o errexit
set -o nounset
set -o pipefail

protoc -I/usr/include -I. \
  -I"${GOPATH}/src" \
  -I"${GOPATH}/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis" \
  --go_out=plugins=grpc:. \
  ./api/v3/clairpb/clair.proto

protoc -I/usr/include -I. \
  -I"${GOPATH}/src" \
  -I"${GOPATH}/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis" \
  --grpc-gateway_out=logtostderr=true:. \
  ./api/v3/clairpb/clair.proto

protoc -I/usr/include -I. \
  -I"${GOPATH}/src" \
  -I"${GOPATH}/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis" \
  --swagger_out=logtostderr=true:. \
  ./api/v3/clairpb/clair.proto

go generate .
