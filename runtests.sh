#!/bin/sh
set -eux

if ! [ -d "apksig_for_tests" ]; then
    git clone --depth=1 -b android-p-preview-1 https://android.googlesource.com/platform/tools/apksig apksig_for_tests
else
    echo "Using cached apksig_for_test directory"
fi

APKSIG_PATH=apksig_for_tests go test -v ./...
