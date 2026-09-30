# Design: Any iPhone (Curated XR + 12/13/14/15) + Live Firmware List Pages

## Context
Current stack is hard-coded to XR `iPhone11,8 MT1A2TH/A REDACTED` in `Dashboard HTML` and `api/status` `device/ipsw_info`. Production hardening already done (persisted `0600` FairPlay, gunicorn `2×4`, `413/429/400`, SQLite WAL `activations.db`, `12 tests`). User wants “full feature all we can do for any iPhone” but scoped to curated list XR + 12/13/14/15 and a firmware list pages dashboard fed live from ipsw.me with local cache.

## Scope
- Supported ProductTypes (curated 13): `iPhone11,8` (XR, n841ap, A12, session), `iPhone12,1` (11), `iPhone13,2` (12), `iPhone14,5` (13), `iPhone15,2` (14 Pro). Maps to `docs/architecture.md` chip table. No exhaustive 30-model matrix.
- Firmware pages: single `GET /firmware` with dropdown `ProductType` + search, backed by live `https://api.ipsw.me/v4/device/{ProductType}` cached 1h in `logs/firmware_cache.json`.
- Any-iPhone activation: `albert_server.py` no hard-coded XR in JS `device` card — reads last activation row’s `ProductType/Model/Serial/UDID` from SQLite, fallback XR if empty.
- Out of scope: per-device tabs, Postgres, download proxying (direct Apple `url`), TSS local (still pass-through), distributed rate limit.

## Architecture
```
GET /firmware (HTML, reuses dashboard dark CSS) ──fetch──> GET /api/devices → [{identifier, name, chip, explain}]
                                      └─fetch─> GET /api/firmwares?productType=iPhone13,2 → {firmwares[], local[], cached, fetchedAt}
                                                       └─> ipsw.me v4/device/{ProductType} (8s timeout) + local scan *.ipsw
                                                       cache logs/firmware_cache.json {ProductType: {fetchedAt, data}} TTL 3600
GET /api/status (existing) device field now dynamic from last activation row, not static XR dict.
```

## Components

### 1. Backend `albert_server.py`
- Constants: `CURATED_DEVICES = [{identifier, name, chip, internal, explain}, ...5]`, `FIRMWARE_CACHE = Path("logs/firmware_cache.json")`, `FIRMWARE_TTL = 3600`, `IPSW_API = "https://api.ipsw.me/v4/device/{ProductType}"`
- Helpers: `def _scan_local_ipsw() -> list[Path]`, `def _fetch_ipsw(productType) -> dict` (requests 8s timeout, try live → cache write → return; except → cache read if fresh → stale flag; else 502), `def _local_overlay(productType) -> list`.
- Routes:
  - `GET /firmware` → `FIRMWARE_HTML` (new dark table page, filter dropdown, signed `✓`/`✗` badge, size `filesize` MB→GB, download link `url`, local `✅` if `identifier in local scan`)
  - `GET /api/devices` → `{"devices": CURATED_DEVICES}`
  - `GET /api/firmwares?productType=iPhone13,2` → `{"productType", "firmwares": [...api.ipsw.me firmwares...], "local": [...], "cached": bool, "fetchedAt": iso, "stale": bool}` (400 if missing/invalid identifier regex `^iPhone\d+,\d+$`)
  - `GET /api/status` tweak: `device` from `SELECT ProductType?` — need to store `ProductType` in activations. Extend `activations` table: add `producttype TEXT` column via `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` in `_init_db`; `log_activation` now takes `productType` from `activation_info.get("ProductType")`; last row query `SELECT producttype,udid,serial FROM activations ORDER BY id DESC LIMIT 1` → `device` dynamic. `ipsw_info` also dynamic: if local IPSW matches `productType` show that file else first local.
- Header: dashboard `h1 Albert — iPhone XR` → `Albert — Any iPhone` (keep XR fallback subtitle).

### 2. Frontend `/firmware` (HTML+JS)
- Reuses dashboard CSS vars (`--bg #0b0f14` etc), header `Albert — Firmware · 18090`.
- `<select id="product">` populated from `/api/devices` (13 curated), `input#q` search (version/build), `table#fw` columns Version | Build | Released | Size | Signed | Local | Download.
- JS: `loadDevices()` → `loadFw(productType)` fetch, render rows, `badge.ok` for `signed`, `✅` if local substring match. Poll not needed; on-change fetch. Error banner for `stale`/`502`.
- Shared redaction: UDID `...2E` not shown here.

### 3. Dashboard ` /dashboard` tweak
- Remove hard-coded `device = {ProductType:iPhone11,8…}` → fetch `device` from `api/status` already does; ensure header title is generic.

## Data Flow
1. User opens `/firmware` → JS `GET /api/devices` → dropdown 5.
2. Picks `iPhone14,5` → JS `GET /api/firmwares?productType=iPhone14,5` → Flask `_fetch_ipsw` → `GET https://api.ipsw.me/v4/device/iPhone14,5` (8s) → `200` parse `firmwares` array `{version, buildid, signed, url, filesize, releasedate}` → write `FIRMWARE_CACHE` → overlay `local` scan → JSON response → table render.
3. Offline: same JS hits cache file `<1h` old → `cached:true`; if >1h and fetch fails → `stale:true` + last data.

## Error Handling
- Invalid `productType` (`!^iPhone\d+,\d+$`): `400 {"error":"invalid ProductType"}`.
- ipsw.me `429/5xx/timeout`: return `cached` data with `stale:true` and `warning` field, status `200` (UI shows yellow badge), unless no cache → `502 {"error":"upsteam unavailable", "retryAfter": 60}`.
- No local IPSW for type: `local: []` (table shows `⬇ Download` only).
- `firmware_cache.json` corrupt: ignore, refetch live; missing dir → `Path.parent.mkdir`.

## Testing
Extend `tests/test_albert.py`:
- `test_firmware_devices`: `GET /api/devices` → 5, identifiers include `iPhone11,8` and `iPhone15,2`.
- `test_firmware_list_cached`: mock `requests.get` for `api.ipsw.me` to return stub `{firmwares:[{version:"18.7.10", buildid:"22H374"}]}`, assert `cached` false first then cached true second call, `signed` field present.
- `test_firmware_local_overlay`: ensure local `iPhone11,8_18.7.10_22H374_Restore.ipsw` appears in `local` for `iPhone11,8` query.
- `test_firmware_page_html`: `GET /firmware` → 200 `text/html` contains `Albert — Firmware`.

Existing `12 tests` remain green (`ruff`, `bandit` `B303/B324 nosec`). `docker compose config` unchanged.

## Security
- No new secrets; ipsw.me is public. `requests` timeout 8s prevents hanging; cache prevents repeated upstream DoS.
- `.gitignore` keeps `*.ipsw` ignored, `*.sha256` kept; `FIRMWARE_CACHE` is in `logs/` (gitignored) so not committed.
- `ALBERT_ACCEPT_RISK` gate still required for activation, not for firmware listing.

## Risks
- ipsw.me rate limit → cache TTL 1h mitigates; stall shows `stale`.
- Local IPSW 8.1G scan `pathlib.Path.glob("*.ipsw")` is O(n) cheap (1 file).
