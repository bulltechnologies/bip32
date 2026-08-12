#!/usr/bin/env bash
#
# Runs the bip32 package test suite against real native backends on the host.
#
# Usage (from repo root):
#   tool/run_host_tests.sh [macos|linux]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEVICE="${1:-macos}"

cd "$ROOT"
flutter pub get

echo "running root package tests"
flutter test --no-pub --exclude-tags benchmark

mkdir -p "$ROOT/example/assets"
cp "$ROOT/test/fixtures.json" "$ROOT/example/assets/fixtures.json"
cp "$ROOT/test/v3_compat_golden.json" "$ROOT/example/assets/v3_compat_golden.json"

cd "$ROOT/example"
flutter pub get
flutter config --enable-swift-package-manager >/dev/null 2>&1 || true
flutter build "$DEVICE" --debug

flutter test integration_test/bip32_suite_test.dart -d "$DEVICE"
flutter test test/widget_test.dart -d "$DEVICE"
