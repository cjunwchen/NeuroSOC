#!/usr/bin/env bash
# Revert the C1 shim. Run from the lab repo root: ./soc-mas/c1/uninstall.sh
set -euo pipefail
LAB="${1:-$(pwd)}"
for a in triage threat_intel remediation; do
  dir="$LAB/agents/$a"
  [ -f "$dir/Dockerfile.orig" ] && mv "$dir/Dockerfile.orig" "$dir/Dockerfile" && echo "  restored agents/$a/Dockerfile"
  rm -f "$dir/shim.py"
done
echo "done. Agents are back to stock (batch) form."
