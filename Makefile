.PHONY: all binary build

IMAGE := clair-dev
CLAIR_IMAGE := clair
DOCKERFILE := Dockerfile.dev
DOCKERFILE_CLAIR := Dockerfile
CLAIR_ENVS :=
CLAIR_MOUNT := -v `pwd`:/go/src/github.com/coreos/clair/
CLAIR_RUN_DOCKER := docker run --rm -i $(CLAIR_ENVS) $(CLAIR_MOUNT) $(IMAGE)

all: build binary clair

build: bundles
	docker build -t "$(IMAGE)" -f "$(DOCKERFILE)" .
binary: build
	$(CLAIR_RUN_DOCKER) go build -o bundles/clair ./cmd/clair
clair:
	docker build -t "$(CLAIR_IMAGE)" -f "$(DOCKERFILE_CLAIR)" .
bundles:
	mkdir bundles
clean:
	rm -rf bundles
