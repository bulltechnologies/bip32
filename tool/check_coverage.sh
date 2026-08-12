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

SUMMARY="$(lcov --extract "$LCOV" '*/lib/*' -o "$ROOT/coverage/lib.info" --quiet 2>&1 && lcov --summary "$ROOT/coverage/lib.info" 2>&1)"
LINES="$(printf '%s\n' "$SUMMARY" | awk '/lines/ {print $2}' | tr -d '%')"
if [ -z "$LINES" ]; then
  echo "error: could not parse line coverage from lcov summary" >&2
  printf '%s\n' "$SUMMARY" >&2
  exit 1
fi

echo "line coverage: ${LINES}% (minimum ${MIN}%)"
awk -v actual="$LINES" -v min="$MIN" 'BEGIN { exit !(actual + 0 >= min + 0) }'
