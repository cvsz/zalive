#!/bin/sh
# Move stray restore logs from root to logs/restore and prune old
set -eu
ROOT="$(cd -- "$(dirname "$0")/.." && pwd)"
LOGS="$ROOT/logs/restore"
mkdir -p "$LOGS"
# move any stray in root
for f in "$ROOT"/restore_*.log; do
  [ -e "$f" ] || continue
  mv -v "$f" "$LOGS"/
done
# prune logs/restore older than 7 days, keep at most 50 newest
find "$LOGS" -type f -name "restore_*.log" -mtime +7 -delete 2>/dev/null || true
# keep only 50 newest numeric probes, but always keep 00008020-* (real device)
find "$LOGS" -type f -name "restore_179*.log" -print0 2>/dev/null | sort -rz | tail -z -n +51 | xargs -0 -r rm -f --
echo "cleanup done: $(find "$LOGS" -type f -name "restore_*.log" 2>/dev/null | wc -l) files in $LOGS"
