FROM armhf/debian:jessie

RUN apt-get update && apt-get install -y apparmor bash-completion btrfs-tools build-essential curl ca-certificates debhelper dh-apparmor dh-systemd git libapparmor-dev libdevmapper-dev libltdl-dev libsqlite3-dev libsystemd-journal-dev --no-install-recommends && rm -rf /var/lib/apt/lists/*

ENV GO_VERSION 1.4.3
RUN curl -fSL "https://github.com/hypriot/golang-armbuilds/releases/download/v${GO_VERSION}/go${GO_VERSION}.linux-armv7.tar.gz" | tar xzC /usr/local
ENV PATH $PATH:/usr/local/go/bin

ENV AUTO_GOPATH 1
ENV DOCKER_BUILDTAGS apparmor selinux
