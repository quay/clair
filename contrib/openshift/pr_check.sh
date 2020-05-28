#!/bin/bash

set -e
# set_root roots this script to the clair repository
set_root() {
    # the repo directory we are trying to root at
    repo="clair"
    # the file system root which indicates search for repo dir failed
    fs_root="/"

    # root yourself at dir containing this script
    p=$(realpath "$0")
    cd $(dirname $p)

    # use basename to walk paths backwards searching for clair
    basename=$(basename `pwd`)
    while [[ $basename != $repo && $basename != $fs_root ]]; do
        cd $(dirname `pwd`)
        basename=$(basename `pwd`)
    done

    # if basename is not clair, we couldn't find the repository root
    if [[ $basename != $repo ]]; then
        return 1
    fi
    return 0
}
if [ ! set_root ]; then
    echo "could not set root to clair repository"
    exit 1
fi

go mod vendor
make container-build
