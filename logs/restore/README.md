# Restore logs — moved to logs/
All `restore_*.log` from idevicerestore probes now live here, not in project root.
- `restore_00008020-001224C81178002E_*.log` — real device start-activate (iPhone XR C8PXJF1EKXKQ) — keep.
- `restore_179*.log` — bulk numeric probes (no Apple USB 05ac, `Unable to discover device mode`) — auto-ignored via .gitignore `restore_179*.log` and `logs/`; safe to delete.
Use: `ls -lt logs/restore/` or `tail -n 20 logs/restore/restore_00008020-*.log` ; `logs/albert.log` and `logs/mitmproxy.log` are the main service logs (see `start.sh` > `logs/albert.log`).
