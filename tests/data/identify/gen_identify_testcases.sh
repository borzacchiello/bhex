#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)
IMAGE_TAG=${IMAGE_TAG:-bhex-identify-fixtures}
HOST_OUT_DIR=${OUT_DIR:-$SCRIPT_DIR/generated}
REL_OUT_DIR=$(python3 -c 'import os, sys; print(os.path.relpath(sys.argv[1], sys.argv[2]))' "$HOST_OUT_DIR" "$ROOT_DIR")
CONTAINER_OUT_DIR="/work/$REL_OUT_DIR"

mkdir -p "$HOST_OUT_DIR"

DOCKER_BUILDKIT=${DOCKER_BUILDKIT:-0} docker build \
    -f "$SCRIPT_DIR/docker/Dockerfile" \
    -t "$IMAGE_TAG" \
    "$SCRIPT_DIR/docker"

docker run --rm \
    --user "$(id -u):$(id -g)" \
    -v "$ROOT_DIR:/work" \
    -w /work \
    "$IMAGE_TAG" \
    python3 tests/data/identify/generate.py --out-dir "$CONTAINER_OUT_DIR"

python3 "$SCRIPT_DIR/generate_asm_snippets.py" \
    --generated-dir "$HOST_OUT_DIR" \
    --output "$ROOT_DIR/tests/data/asm_snippets.h"
