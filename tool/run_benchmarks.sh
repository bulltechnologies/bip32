#!/usr/bin/env bash
#
# Runs profile-mode microbenchmarks (stdout timings for CI log capture).
#
# Usage (from repo root):
#   tool/run_benchmarks.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
flutter pub get
flutter test --no-pub --profile test/benchmark/
