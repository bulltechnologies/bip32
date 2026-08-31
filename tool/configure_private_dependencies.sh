#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${DEPENDENCY_TOKEN:-}" ]]; then
  echo "::error::Missing BIP_DEPENDENCY_TOKEN Actions secret; it must have read access to native_crypto and native_sig."
  exit 1
fi

git config --global \
  url."https://x-access-token:${DEPENDENCY_TOKEN}@github.com/bulltechnologies/".insteadOf \
  "https://github.com/bulltechnologies/"
