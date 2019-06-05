#!/bin/bash

set -e
# if minikube is running configure docker
# env vars to push to minikube
if [ -x "$(command -v minikube)" ] && minikube status; then
    eval $(minikube docker-env)
fi
docker build -t clair-local:latest .
