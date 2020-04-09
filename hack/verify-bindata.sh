#!/usr/bin/env bash
set -euo pipefail

echo "Verifying pkg/assets/bindata.go is up to date"

TMP_OUTPUT="$(mktemp)"

REPO_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )/.."

OUTPUT_FILE="${TMP_OUTPUT}" "${REPO_DIR}/hack/update-bindata.sh"

diff -Naup ${REPO_DIR}/pkg/assets/bindata.go "${TMP_OUTPUT}"
