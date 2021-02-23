#!/bin/sh
set -eux

if ! [ -d "apksig_for_tests" ]; then
    git clone --depth=1 -b android-s-preview-1 https://android.googlesource.com/platform/tools/apksig apksig_for_tests
else
    echo "Using cached apksig_for_test directory"
fi

export APKSIG_PATH=apksig_for_tests

if ([ -n ${GIMME_ARCH+x} ] && [ "$GIMME_ARCH" = "amd64" ]) || ([ -z ${GIMME_ARCH+x} ] && go version | grep amd64 -q); then
    go test -race -parallel 8 -v ./...
else
    go test -v ./...
fi
