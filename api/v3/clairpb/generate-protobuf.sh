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

DOCKER_REPO_ROOT="$GOPATH/src/github.com/coreos/clair"
IMAGE=${IMAGE:-"quay.io/coreos/clair-gen-proto"}

docker run --rm -it \
  -v "$DOCKER_REPO_ROOT":"$DOCKER_REPO_ROOT" \
  -w "$DOCKER_REPO_ROOT" \
  "$IMAGE" \
  "./api/v3/clairpb/run_in_docker.sh"
