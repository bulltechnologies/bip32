#!/usr/bin/env bash
#
# Verifies lib/ line coverage from `flutter test --coverage` output.
#
# Usage:
#   tool/check_coverage.sh [minimum_percent]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MIN="${1:-70}"
LCOV="$ROOT/coverage/lcov.info"

if [ ! -f "$LCOV" ]; then
  echo "error: missing $LCOV; run flutter test --coverage first" >&2
  exit 1
fi

if ! command -v lcov >/dev/null 2>&1; then
  echo "error: lcov is required (e.g. apt-get install lcov)" >&2
  exit 1
fi

# Flutter may emit source paths as either `lib/...` (relative) or
# `<checkout>/lib/...` (absolute), depending on the toolchain. Select the
# matching form so newer lcov versions do not reject an unused pattern.
LIB_PATTERN='*/lib/*'
if grep -q '^SF:lib/' "$LCOV"; then
  LIB_PATTERN='lib/*'
fi
# Flutter's tracefile carries line coverage only. Disable function coverage so
# lcov 2.x does not reject the otherwise valid file for missing FN records.
SUMMARY="$(lcov --rc function_coverage=0 --extract "$LCOV" "$LIB_PATTERN" -o "$ROOT/coverage/lib.info" --quiet 2>&1 && lcov --rc function_coverage=0 --summary "$ROOT/coverage/lib.info" 2>&1)"
LINES="$(printf '%s\n' "$SUMMARY" | awk '/lines/ {print $2}' | tr -d '%')"
if [ -z "$LINES" ]; then
  echo "error: could not parse line coverage from lcov summary" >&2
  printf '%s\n' "$SUMMARY" >&2
  exit 1
fi

echo "line coverage: ${LINES}% (minimum ${MIN}%)"
awk -v actual="$LINES" -v min="$MIN" 'BEGIN { exit !(actual + 0 >= min + 0) }'
