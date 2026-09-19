#!/usr/bin/env bash
# Bootstrap the development environment (Python toolchain only — scanner
# binaries are system packages: nmap, and optionally masscan/fping/arp-scan).
set -euo pipefail
cd "$(dirname "$0")/.."

uv sync --locked --all-groups

echo
echo "Done. Try:"
echo "  uv run secman-intra-mon capabilities"
echo "  uv run secman-intra-mon discover --dry-run"
