#!/usr/bin/env bash
# Aggregate test gate: runs every service's assert-based test_*.py.
# PYBIN overrides the interpreter (e.g. a local venv); defaults to `python` for CI.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SHARED="$ROOT/shared"

PYBIN="${PYBIN:-python}"
if command -v "$PYBIN" >/dev/null 2>&1; then
  PYBIN="$(command -v "$PYBIN")"
else
  PYBIN="$(cd "$(dirname "$PYBIN")" && pwd)/$(basename "$PYBIN")"
fi

# Service tests import the shared modules (ndr_runtime/metrics/store) that the
# images COPY in flat; make them importable here via PYTHONPATH.
export PYTHONPATH="$SHARED"

run_dir() {
  local dir="$1"
  [ -d "$dir" ] || return 0
  echo "== $dir =="
  # nullglob: a dir with no test files (e.g. flink) is a clean no-op, not an error.
  ( cd "$dir"; shopt -s nullglob; for t in test_*.py; do "$PYBIN" "$t" || exit 1; done; exit 0 )
}

run_dir "$ROOT/shared"
run_dir "$ROOT/contracts"
for d in "$ROOT"/services/*/; do run_dir "$d"; done

echo "all tests passed"
