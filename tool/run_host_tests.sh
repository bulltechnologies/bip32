#!/usr/bin/env bash
#
# Runs the bip32 package test suite against real native backends on the host.
#
# Usage (from repo root):
#   tool/run_host_tests.sh [macos|linux]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEVICE="${1:-macos}"
NATIVE_SIG_REF="375accd28ce9a0fda74ad91334983bc7c35f3ea0"

cd "$ROOT"
flutter pub get

mkdir -p "$ROOT/example/assets"
cp "$ROOT/test/fixtures.json" "$ROOT/example/assets/fixtures.json"
cp "$ROOT/test/v3_compat_golden.json" "$ROOT/example/assets/v3_compat_golden.json"

NATIVE_SIG_CACHE="$(find "$HOME/.pub-cache/git" -maxdepth 1 -name "native_sig-${NATIVE_SIG_REF}" -type d | head -1)"
if [ -z "$NATIVE_SIG_CACHE" ]; then
  echo "error: native_sig git checkout not found; run flutter pub get first" >&2
  exit 1
fi

echo "building native_sig host library from $NATIVE_SIG_CACHE"
(
  cd "$NATIVE_SIG_CACHE"
  dart run tool/verify_vendored_backends.dart
  tool/build_host.sh
)

HOST_LIB="$NATIVE_SIG_CACHE/build/host/libnative_sig.so"
if [ "$(uname -s)" = "Darwin" ]; then
  HOST_LIB="$NATIVE_SIG_CACHE/build/host/libnative_sig.dylib"
fi
echo "built native_sig host library at $HOST_LIB"

cd "$ROOT/example"
flutter pub get
flutter config --enable-swift-package-manager >/dev/null 2>&1 || true
flutter build "$DEVICE" --debug

if [ "$DEVICE" = "linux" ]; then
  export NATIVE_SIG_LIBRARY_PATH="$HOST_LIB"
  echo "using NATIVE_SIG_LIBRARY_PATH=$NATIVE_SIG_LIBRARY_PATH"
else
  unset NATIVE_SIG_LIBRARY_PATH
fi

flutter test integration_test/bip32_suite_test.dart -d "$DEVICE"
flutter test test/widget_test.dart -d "$DEVICE"
