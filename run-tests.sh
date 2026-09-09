#!/usr/bin/env bash
# Aggregate test gate: runs every service's assert-based test_*.py.
# PYBIN overrides the interpreter (e.g. a local venv); defaults to `python` for CI/images.
set -euo pipefail

PYBIN="${PYBIN:-python}"
# Resolve to an absolute path so it survives the `cd` into each test dir.
if command -v "$PYBIN" >/dev/null 2>&1; then
  PYBIN="$(command -v "$PYBIN")"
else
  PYBIN="$(cd "$(dirname "$PYBIN")" && pwd)/$(basename "$PYBIN")"
fi

run_dir() {
  local dir="$1"
  [ -d "$dir" ] || return 0
  echo "== $dir =="
  ( cd "$dir" && for t in test_*.py; do [ -e "$t" ] && "$PYBIN" "$t"; done )
}

run_dir shared
run_dir contracts
for d in services/*/; do run_dir "$d"; done

echo "all tests passed"
