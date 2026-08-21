#!/usr/bin/env bash
# Layer the C1 shim onto the three batch agents. Run from the lab repo root:
#   ./soc-mas/c1/install.sh
# agent.py is NOT modified; the original Dockerfile is saved as Dockerfile.orig.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LAB="${1:-$(pwd)}"
for a in triage threat_intel remediation; do
  dir="$LAB/agents/$a"
  [ -d "$dir" ] || { echo "!! missing $dir — run from the lab repo root or pass its path"; exit 1; }
  [ -f "$dir/Dockerfile.orig" ] || cp "$dir/Dockerfile" "$dir/Dockerfile.orig"
  cp "$HERE/shim.py" "$dir/shim.py"
  cp "$HERE/Dockerfile.shim" "$dir/Dockerfile"
  echo "  shimmed agents/$a"
done
echo "done. Now bring it up:"
echo "  docker compose -f docker-compose.yml -f soc-mas/c1/compose.c1.yml up -d --build"
echo "  open http://localhost:8020"
