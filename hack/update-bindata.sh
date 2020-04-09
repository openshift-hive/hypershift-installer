#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="$(git rev-parse --show-toplevel)"

OUTPUT_FILE="${OUTPUT_FILE:-./pkg/assets/bindata.go}"

cd "${SRC_DIR}"

# ensure go-bindata
GOBIN=${SRC_DIR}/bin go install github.com/jteeuwen/go-bindata/go-bindata

# go-bindata generates code assets from the yaml we want to deploy by the operator.
"./bin/go-bindata" \
        -nocompress \
        -nometadata \
        -pkg "assets" \
	-prefix "assets/" \
        -o "${OUTPUT_FILE}" \
        -ignore "OWNERS" \
        -ignore ".*\.sw.?" \
	./assets/... && \
gofmt -s -w "${OUTPUT_FILE}"
