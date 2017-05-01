.PHONY: dbuild man \
	    localtest localunittest localintegration \
	    test unittest integration

PREFIX := $(DESTDIR)/usr/local
BINDIR := $(PREFIX)/sbin
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null)
GIT_BRANCH_CLEAN := $(shell echo $(GIT_BRANCH) | sed -e "s/[^[:alnum:]]/-/g")
RUNC_IMAGE := runc_dev$(if $(GIT_BRANCH_CLEAN),:$(GIT_BRANCH_CLEAN))
PROJECT := github.com/opencontainers/runc
TEST_DOCKERFILE := script/test_Dockerfile
BUILDTAGS := seccomp
COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
COMMIT := $(if $(shell git status --porcelain --untracked-files=no),"${COMMIT_NO}-dirty","${COMMIT_NO}")
RUNC_LINK := $(CURDIR)/Godeps/_workspace/src/github.com/opencontainers/runc
export GOPATH := $(CURDIR)/Godeps/_workspace

MAN_DIR := $(CURDIR)/man/man8
MAN_PAGES = $(shell ls $(MAN_DIR)/*.8)
MAN_PAGES_BASE = $(notdir $(MAN_PAGES))
MAN_INSTALL_PATH := ${PREFIX}/share/man/man8/

RELEASE_DIR := $(CURDIR)/release

VERSION := ${shell cat ./VERSION}

SHELL := $(shell command -v bash 2>/dev/null)

all: $(RUNC_LINK)
	go build -i -ldflags "-X main.gitCommit=${COMMIT} -X main.version=${VERSION}" -tags "$(BUILDTAGS)" -o runc .

static: $(RUNC_LINK)
	CGO_ENABLED=1 go build -i -tags "$(BUILDTAGS) cgo static_build" -ldflags "-w -extldflags -static -X main.gitCommit=${COMMIT} -X main.version=${VERSION}" -o runc .

release: $(RUNC_LINK)
	@flag_list=(seccomp selinux apparmor static); \
	unset expression; \
	for flag in "$${flag_list[@]}"; do \
		expression+="' '{'',$${flag}}"; \
	done; \
	eval profile_list=("$$expression"); \
	for profile in "$${profile_list[@]}"; do \
		output=${RELEASE_DIR}/runc; \
		for flag in $$profile; do \
			output+=."$$flag"; \
		done; \
		tags="$$profile"; \
		ldflags="-X main.gitCommit=${COMMIT} -X main.version=${VERSION}"; \
		CGO_ENABLED=; \
		[[ "$$profile" =~ static ]] && { \
			tags="$${tags/static/static_build}"; \
			tags+=" cgo"; \
			ldflags+=" -w -extldflags -static"; \
			CGO_ENABLED=1; \
		}; \
		echo "Building target: $$output"; \
		rm -rf "${GOPATH}/pkg"; \
		go build -i -ldflags "$$ldflags" -tags "$$tags" -o "$$output" .; \
	done

$(RUNC_LINK):
	ln -sfn $(CURDIR) $(RUNC_LINK)

dbuild: runcimage
	docker run --rm -v $(CURDIR):/go/src/$(PROJECT) --privileged $(RUNC_IMAGE) make

lint:
	go vet ./...
	go fmt ./...

man:
	man/md2man-all.sh

runcimage:
	docker build -t $(RUNC_IMAGE) .

test:
	make unittest integration

localtest:
	make localunittest localintegration

unittest: runcimage
	docker run -e TESTFLAGS -ti --privileged --rm -v $(CURDIR):/go/src/$(PROJECT) $(RUNC_IMAGE) make localunittest

localunittest: all
	go test -timeout 3m -tags "$(BUILDTAGS)" ${TESTFLAGS} -v ./...

integration: runcimage
	docker run -e TESTFLAGS -t --privileged --rm -v $(CURDIR):/go/src/$(PROJECT) $(RUNC_IMAGE) make localintegration

localintegration: all
	bats -t tests/integration${TESTFLAGS}

install:
	install -D -m0755 runc $(BINDIR)/runc

install-bash:
	install -D -m0644 contrib/completions/bash/runc $(PREFIX)/share/bash-completion/completions/runc

install-man:
	install -d -m 755 $(MAN_INSTALL_PATH)
	install -m 644 $(MAN_PAGES) $(MAN_INSTALL_PATH)

uninstall:
	rm -f $(BINDIR)/runc

uninstall-bash:
	rm -f $(PREFIX)/share/bash-completion/completions/runc

uninstall-man:
	rm -f $(addprefix $(MAN_INSTALL_PATH),$(MAN_PAGES_BASE))

clean:
	rm -f runc
	rm -f $(RUNC_LINK)
	rm -rf $(GOPATH)/pkg
	rm -rf $(RELEASE_DIR)

validate:
	script/validate-gofmt
	go vet ./...

ci: validate localtest
