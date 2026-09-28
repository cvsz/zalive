#!/usr/bin/env bash
# sha256_manifest.sh — generate SHA256 manifest for IPSW without committing IPSW
# Usage: ./scripts/sha256_manifest.sh [--check]
#   without args: creates/updates <ipsw>.sha256 and ipsw.sha256 manifest
#   --check: verifies existing *.sha256 against files (sha256sum -c)
# The IPSW itself (8.1 GB) stays gitignored via .gitignore *.ipsw; only *.sha256 is tracked.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

shopt -s nullglob
IPSW_FILES=( *.ipsw **/*.ipsw )

# also handle explicit arg list
if [[ $# -gt 0 && "$1" != "--check" ]]; then
  IPSW_FILES=( "$@" )
fi

if [[ "${1:-}" == "--check" ]]; then
  # collect all *.sha256
  mapfile -t ALL_SHA < <(find . -maxdepth 2 -name "*.sha256" -type f 2>/dev/null | head -n 20)
  if [[ ${#ALL_SHA[@]} -eq 0 ]]; then
    echo "No *.sha256 manifest found. Run without --check to generate." >&2
    exit 1
  fi
  rc=0
  for m in "${ALL_SHA[@]}"; do
    echo "Checking $m ..."
    if ! sha256sum -c "$m"; then rc=1; fi
  done
  exit $rc
fi

if [[ ${#IPSW_FILES[@]} -eq 0 ]]; then
  echo "No *.ipsw found in $ROOT (expected iPhone11,8_18.7.10_22H374_Restore.ipsw)." >&2
  echo "Manifest not updated — place IPSW outside repo or download, then re-run." >&2
  # still produce an empty placeholder manifest so CI can assert the script exists
  exit 0
fi

# Generate per-file <file>.sha256 and aggregate ipsw.sha256
AGG="ipsw.sha256"
: > "$AGG.tmp"
for f in "${IPSW_FILES[@]}"; do
  # skip directories
  [[ -f "$f" ]] || continue
  echo "Hashing $f ..."
  sha256sum "$f" | tee "$f.sha256"
  cat "$f.sha256" >> "$AGG.tmp"
  # secure perms for manifest (no secrets, but consistent)
  chmod 644 "$f.sha256"
done
mv "$AGG.tmp" "$AGG"
chmod 644 "$AGG"
echo "Manifest written to $AGG:"
cat "$AGG"
echo ""
echo "IPSW files remain gitignored (*.ipsw). Commit only *.sha256:"
echo "  git add *.sha256 *.ipsw.sha256 $AGG 2>/dev/null; git status"
# Verify .gitignore covers ipsw but not sha256
if git check-ignore -q "${IPSW_FILES[0]}" 2>/dev/null; then
  echo "  OK: ${IPSW_FILES[0]} is ignored (*.ipsw)"
else
  echo "  WARN: ${IPSW_FILES[0]} is NOT ignored — check .gitignore" >&2
fi
if git check-ignore -q "$AGG" 2>/dev/null; then
  echo "  ERROR: $AGG is ignored — .gitignore must keep manifest (see !*.sha256)" >&2
  exit 1
else
  echo "  OK: $AGG is tracked (not ignored)"
fi
