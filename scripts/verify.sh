#!/usr/bin/env bash
# Gate before every commit: lockfile, lint, format, types, build.
set -euo pipefail
cd "$(dirname "$0")/.."

uv lock --check
uv run ruff check
uv run ruff format --check
uv run mypy src/secman_intra_mon
uv build
