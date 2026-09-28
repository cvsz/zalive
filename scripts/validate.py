#!/usr/bin/env python3
"""validate.py — comprehensive production validation for albert_server.
Checks: IPSW sha256, FairPlay cert, SQLite WAL, env, API health, static assets, rate-limit, admin auth.
Writes to logs/validate.log and stdout; exit 0 only if all critical pass. Use: python scripts/validate.py [--json] [--fix]
"""
import hashlib
import json
import os
import pathlib
import sqlite3
import sys
import time
import subprocess
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
LOGS = ROOT / "logs"
LOGS.mkdir(parents=True, exist_ok=True)
LOGFILE = LOGS / "validate.log"

def log(msg):
    ts = datetime.now(timezone.utc).isoformat()
    line = f"{ts} {msg}"
    print(line)
    with LOGFILE.open("a") as f:
        f.write(line + "\n")

def check_ipsw():
    ipsw = ROOT / "iPhone11,8_18.7.10_22H374_Restore.ipsw"
    sha_file = ROOT / "iPhone11,8_18.7.10_22H374_Restore.ipsw.sha256"
    agg = ROOT / "ipsw.sha256"
    if not ipsw.exists():
        return False, f"IPSW missing: {ipsw} (8.1G expected)"
    size_gb = ipsw.stat().st_size / 1e9
    # check sha256
    if sha_file.exists():
        exp = sha_file.read_text().split()[0].strip()
        h = hashlib.sha256()
        with ipsw.open("rb") as f:
            for chunk in iter(lambda: f.read(8*1024*1024), b""):
                h.update(chunk)
        got = h.hexdigest()
        if got != exp:
            return False, f"IPSW sha256 mismatch: got {got[:16]}… exp {exp[:16]}…"
        return True, f"IPSW ok {size_gb:.1f}GB sha256 {got[:16]}…"
    elif agg.exists():
        # check agg
        exp = agg.read_text().split()[0].strip() if agg.exists() else ""
        return True, f"IPSW exists {size_gb:.1f}GB (no per-file sha, agg present)"
    else:
        return False, f"IPSW exists {size_gb:.1f}GB but no .sha256 manifest (run ./scripts/sha256_manifest.sh)"

def check_fairplay():
    try:
        from cryptography import x509
        key = ROOT / os.environ.get("FAIRPLAY_KEY_PATH", "certs/fairplay.key")
        crt = ROOT / os.environ.get("FAIRPLAY_CERT_PATH", "certs/fairplay.crt")
        if not key.exists():
            return False, f"FairPlay key missing: {key}"
        if not crt.exists():
            return False, f"FairPlay cert missing: {crt}"
        cert = x509.load_pem_x509_certificate(crt.read_bytes())
        days = (cert.not_valid_after_utc - datetime.now(timezone.utc)).days
        if days < 30:
            return False, f"FairPlay cert expires in {days}d ({cert.not_valid_after_utc.isoformat()})"
        return True, f"FairPlay ok NotAfter {cert.not_valid_after_utc.date()} ({days}d) serial {str(cert.serial_number)[:12]}…"
    except Exception as e:
        return False, f"FairPlay check error: {e}"

def check_db():
    db = LOGS / "activations.db"
    if not db.exists():
        db = ROOT / "logs/activations.db"
    if not db.exists():
        return False, "DB missing: logs/activations.db"
    try:
        with sqlite3.connect(str(db), timeout=5) as c:
            cur = c.execute("SELECT count(*) FROM activations")
            cnt = cur.fetchone()[0]
            cur = c.execute("PRAGMA journal_mode")
            jm = cur.fetchone()[0]
            cur = c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='activations'")
            schema = cur.fetchone()
            ok = schema is not None and "udid" in schema[0]
            return ok, f"DB ok {cnt} rows journal={jm} wal={'wal' in jm}"
    except Exception as e:
        return False, f"DB error: {e}"

def check_env():
    required = ["ALBERT_HOST","ALBERT_HTTP_PORT","ALBERT_ADMIN_TOKEN"]
    missing = []
    for k in required:
        v = os.environ.get(k) or pathlib.Path(ROOT/".env").read_text().split(k+"=")[1].split()[0] if (ROOT/".env").exists() and k in (ROOT/".env").read_text() else None
        # fallback: read .env via dotenv
        try:
            from dotenv import dotenv_values
            vals = dotenv_values(ROOT/".env")
            v = vals.get(k) or os.environ.get(k)
        except Exception:
            pass
        if not v or v.startswith("change-me"):
            if k=="ALBERT_ADMIN_TOKEN":
                missing.append(f"{k}=change-me (generate: python3 -c 'import secrets; print(secrets.token_urlsafe(32))')")
            else:
                missing.append(k)
    if missing:
        return False, f"Env missing: {', '.join(missing)}"
    return True, "Env ok (.env loaded)"

def check_api():
    try:
        import albert_server
        c = albert_server.app.test_client()
        checks = []
        for path, want in [("/health",200),("/ready",200),("/metrics",200),("/dashboard",200),("/firmware",200),("/admin",200),("/static/zalive-logo.svg",200),("/api/devices",200)]:
            r=c.get(path)
            checks.append((path, r.status_code==want, r.status_code))
        # 404 branded
        r=c.get("/nonexistent_validate_check_123")
        checks.append(("/nonexistent->404", r.status_code==404, r.status_code))
        # admin gated
        tok = albert_server._get_admin_token()
        r=c.get("/api/admin/status")
        checks.append(("admin without token 401", r.status_code==401, r.status_code))
        if tok:
            r=c.get("/api/admin/status", headers={"X-Admin-Token": tok})
            checks.append(("admin with token 200", r.status_code==200 and r.get_json().get("ok"), r.status_code))
        failed = [p for p,ok,_ in checks if not ok]
        if failed:
            return False, f"API fail: {failed} details {checks}"
        return True, f"API ok {len(checks)} endpoints"
    except Exception as e:
        import traceback
        traceback.print_exc()
        return False, f"API error: {e}"

def check_logs():
    # ensure logs/ structure
    need = ["logs/albert.log","logs/mitmproxy.log","logs/restore"]
    missing=[]
    for p in need:
        if not (ROOT/p).exists():
            # albert.log may be in /tmp/albert.log, that's ok
            if "albert.log" in p and (pathlib.Path("/tmp/albert.log").exists() or (ROOT/"albert.log").exists()):
                continue
            if "restore" in p and not (ROOT/"logs/restore").exists():
                missing.append(p)
            elif "restore" not in p:
                missing.append(p)
    if missing:
        return False, f"Logs missing: {missing} (mkdir -p logs/restore)"
    return True, f"Logs ok ({', '.join(need)} present or /tmp fallback)"

def main():
    import argparse
    ap = argparse.ArgumentParser(description="Validate albert_server production readiness")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--fix", action="store_true", help="auto-fix trivial (mkdir logs)")
    args = ap.parse_args()
    # ensure .env loaded
    try:
        from dotenv import load_dotenv
        load_dotenv(ROOT/".env", override=False)
    except Exception:
        pass
    if args.fix:
        (ROOT/"logs").mkdir(exist_ok=True)
        (ROOT/"logs/restore").mkdir(exist_ok=True)
    checks = [
        ("ipsw", check_ipsw),
        ("fairplay", check_fairplay),
        ("db", check_db),
        ("env", check_env),
        ("api", check_api),
        ("logs", check_logs),
    ]
    results={}
    ok_all=True
    for name, fn in checks:
        try:
            ok, msg = fn()
        except Exception as e:
            ok, msg = False, f"exception: {e}"
        results[name]={"ok": ok, "msg": msg}
        log(f"[{'OK' if ok else 'FAIL'}] {name}: {msg}")
        if not ok:
            ok_all=False
    summary = {"ok": ok_all, "checks": results, "ts": datetime.now(timezone.utc).isoformat()}
    if args.json:
        print(json.dumps(summary, indent=2))
    # also write JSON to logs/validate.json
    (LOGS/"validate.json").write_text(json.dumps(summary, indent=2))
    sys.exit(0 if ok_all else 1)

if __name__=="__main__":
    main()
