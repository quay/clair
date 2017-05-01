#!/bin/sh
set -e
set -x

. $(dirname "$0")/binaries-commits

RM_GOPATH=0

TMP_GOPATH=${TMP_GOPATH:-""}

if [ -z "$TMP_GOPATH" ]; then
	export GOPATH="$(mktemp -d)"
	RM_GOPATH=1
else
	export GOPATH="$TMP_GOPATH"
fi

# Do not build with ambient capabilities support
RUNC_BUILDTAGS="${RUNC_BUILDTAGS:-"seccomp apparmor selinux"}"

install_runc() {
	echo "Install runc version $RUNC_COMMIT"
	git clone https://github.com/docker/runc.git "$GOPATH/src/github.com/opencontainers/runc"
	cd "$GOPATH/src/github.com/opencontainers/runc"
	git checkout -q "$RUNC_COMMIT"
	make BUILDTAGS="$RUNC_BUILDTAGS" $1
	cp runc /usr/local/bin/docker-runc
}

install_containerd() {
	echo "Install containerd version $CONTAINERD_COMMIT"
	git clone https://github.com/docker/containerd.git "$GOPATH/src/github.com/docker/containerd"
	cd "$GOPATH/src/github.com/docker/containerd"
	git checkout -q "$CONTAINERD_COMMIT"
	make $1
	cp bin/containerd /usr/local/bin/docker-containerd
	cp bin/containerd-shim /usr/local/bin/docker-containerd-shim
	cp bin/ctr /usr/local/bin/docker-containerd-ctr
}

install_proxy() {
	echo "Install docker-proxy version $LIBNETWORK_COMMIT"
	git clone https://github.com/docker/libnetwork.git "$GOPATH/src/github.com/docker/libnetwork"
	cd "$GOPATH/src/github.com/docker/libnetwork"
	git checkout -q "$LIBNETWORK_COMMIT"
	go build -ldflags="$PROXY_LDFLAGS" -o /usr/local/bin/docker-proxy github.com/docker/libnetwork/cmd/proxy
}

install_bindata() {
    echo "Install go-bindata version $BINDATA_COMMIT"
    git clone https://github.com/jteeuwen/go-bindata "$GOPATH/src/github.com/jteeuwen/go-bindata"
    cd $GOPATH/src/github.com/jteeuwen/go-bindata
    git checkout -q "$BINDATA_COMMIT"
	go build -o /usr/local/bin/go-bindata github.com/jteeuwen/go-bindata/go-bindata
}

for prog in "$@"
do
	case $prog in
		tomlv)
			echo "Install tomlv version $TOMLV_COMMIT"
			git clone https://github.com/BurntSushi/toml.git "$GOPATH/src/github.com/BurntSushi/toml"
			cd "$GOPATH/src/github.com/BurntSushi/toml" && git checkout -q "$TOMLV_COMMIT"
			go build -v -o /usr/local/bin/tomlv github.com/BurntSushi/toml/cmd/tomlv
			;;

		runc)
			install_runc static
			;;

		runc-dynamic)
			install_runc
			;;

		containerd)
			install_containerd static
			;;

		containerd-dynamic)
			install_containerd
			;;

		tini)
			echo "Install tini version $TINI_COMMIT"
			git clone https://github.com/krallin/tini.git "$GOPATH/tini"
			cd "$GOPATH/tini"
			git checkout -q "$TINI_COMMIT"
			cmake .
			make tini-static
			cp tini-static /usr/local/bin/docker-init
			;;

		proxy)
			export CGO_ENABLED=0
			install_proxy
			;;

		proxy-dynamic)
			PROXY_LDFLAGS="-linkmode=external" install_proxy
			;;

		vndr)
			echo "Install vndr version $VNDR_COMMIT"
			git clone https://github.com/LK4D4/vndr.git "$GOPATH/src/github.com/LK4D4/vndr"
			cd "$GOPATH/src/github.com/LK4D4/vndr"
			git checkout -q "$VNDR_COMMIT"
			go build -v -o /usr/local/bin/vndr .
			;;

        bindata)
            install_bindata
            ;;

		*)
			echo echo "Usage: $0 [tomlv|runc|containerd|tini|proxy]"
			exit 1

	esac
done

if [ $RM_GOPATH -eq 1 ]; then
	rm -rf "$GOPATH"
fi
