# Implementation Plan — iPhone XR USB Activation Reverse Engineering & Optimization

## Phase 1: Deep Codebase Analysis (Complete)
- Explored `activate_device.py` (857 lines) — activation client with DRM handshake, device activation, session mode
- Explored `albert_server.py` (1106+ lines) — Flask Albert server with full activation flow, rate limiting, mTLS, SQLite persistence
- Reviewed all documentation in `docs/` — IMEI_ACTIVATION_REVERSE_ENGINEERING.md, IPSW_REVERSE_ENGINEERING.md, DEVICE_GUIDE.md, architecture.md
- Reviewed GitHub workflows — ci.yml, automated-audit-review-approve.yml, auto-fix-open-prs.yml
- Checked git credentials at `/home/cvsz/.config/gh/.git-credentials`

## Phase 2: iPhone XR USB Activation Features (In Progress)
### 2.1 Reverse-Engineer XR-Specific USB Activation
- iPhone XR = `iPhone11,8` (A12 chip, CPID 0x8020, BoardConfig n841ap)
- Current `CURATED_DEVICES` already includes iPhone XR at line 71 of albert_server.py
- Need to ensure `deviceActivation` endpoint properly handles iPhone11,8 product type
- Verify `drmHandshake` session flow works with XR (stub response noted in architecture.md)

### 2.2 USB Connection & Device Detection
- `activate_device.py` uses usbmuxd via `pymobiledevice3` or `libimobiledevice`
- `get_device_info()` resolves UDID across API generations (serial/udid/identifier/udid_) 
- Need to ensure UDID matching works for XR devices on USB

## Phase 3: Performance Optimization (In Progress)
### 3.1 Activation Flow Optimization
- Current `_post_with_retry` has exponential backoff (1s, 2s, 4s) + 413/429/5xx handling + circuit breaker
- Optimize by reducing unnecessary retries for client errors
- Add connection pooling optimization

### 3.2 Rate Limiting Efficiency
- Per-IP 100/min + per-UDID 10/min (in-memory + Redis optional)
- Optimize pruning logic to reduce overhead under load
- Add metrics for rate limit hit rates

### 3.3 Plist Handling Optimization
- Current: `plistlib.dumps()` → `base64.b64encode()` — standard, no changes needed
- Ensure minimal payload size (<512KB MAX_CONTENT_LENGTH)

### 3.4 FairPlay Key Loading
- Current: loaded once in `AlbertServer.__init__`, `0600` perms
- Optimize: hot-reload on demand without full restart

## Phase 4: Missing Features (In Progress)
### 4.1 IMEI Luhn Validation (Optional)
- Currently `_validate_imei` skips Luhn check by default
- Add `ALBERT_IMEI_LUHN=1` env toggle to enforce Luhn (Apple enforces it)
- Already has `_luhn_check()` function at line 916 of albert_server.py

### 4.2 Sync Activated State Persistence
- After activation, persist sync state (push token, APNs topic, Find My, iCloud, carrier)
- `sync_state` table already exists but needs activation flow integration

### 4.3 API Endpoint Enhancements
- Ensure `/api/device_info` returns proper data with auth
- Add `/api/activation-status` endpoint
- Enhance `/api/status` with more detail

### 4.4 Direct IMEI Activation Flow
- Currently `activate_device.py` has no `--imei` flag
- Add support for passing IMEI directly for testing

### 4.5 Session Mode DRM Handshake Improvement
- Current drmHandshake returns stub response (cannot pass Apple's FairPlay)
- Add better error handling and fallback options

## Phase 5: Documentation Updates (Planned)
- Update README.md with current state
- Update architecture.md with performance notes
- Update IMEI_ACTIVATION_REVERSE_ENGINEERING.md with implementation details
- Update all markdown syntax and consistency

## Phase 6: Git & GitHub Operations (Planned)
- Use `/home/cvsz/.config/gh/.git-credentials` for auth
- `gh auth switch -u cvsz` for GPG commits & PR opening
- `gh auth switch -u policedbc` for audit + review + approve
- `gh auth switch -u cvsz` for merge

---
**Status**: Phase 2-4 in progress, Phase 5-6 pending code changes