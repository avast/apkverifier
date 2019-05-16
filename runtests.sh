#!/bin/sh
set -eux

if [ -n "${GIMME_OS:-}" ] && [ "$GIMME_OS" != "linux" ]; then
    echo "Non-linux travis platform, skipping tests..."
    exit 0
fi

if ! [ -d "apksig_for_tests" ]; then
    git clone --depth=1 -b oreo-mr1-iot-release https://android.googlesource.com/platform/tools/apksig apksig_for_tests
else
    echo "Using cached apksig_for_test directory"
fi

APKSIG_PATH=apksig_for_tests go test -v ./...
