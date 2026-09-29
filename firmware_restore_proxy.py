# Firmware Restore Proxy Configuration - FIXED
# Use with mitmproxy to intercept and redirect iOS firmware restore traffic
# Installation: pip install mitmproxy
# Usage: mitmproxy -s firmware_restore_proxy.py --set block_global=false
#        or mitmweb -s firmware_restore_proxy.py --set block_global=false
from mitmproxy import http, ctx
import os
import pathlib

# Only intercept activation hosts locally; TSS/gs.apple.com should go to Apple unless you run a local TSS server.
# Previous version incorrectly redirected gs.apple.com, osrecovery, etc. to local Albert which breaks restore.
ALBERT_HOSTS = [
    "albert.apple.com",
]
# Optional: hosts that can be redirected if you have a local TSS implementation
TSS_HOSTS = [
    # "gs.apple.com",  # Uncomment only if you implement local TSS (not included)
]
# Keep original lists for logging but don't redirect by default
LOGGING_KEYWORDS_HOSTS = [
    "albert.apple.com",
    "gs.apple.com",
    "osrecovery.apple.com",
    "appldnld.apple.com",
    "mesu.apple.com",
]

# Resolve local Albert server address.
# Supports env override for docker: LOCAL_ALBERT_HOST=albert-server
LOCAL_ALBERT_HOST = os.environ.get("LOCAL_ALBERT_HOST", "127.0.0.1")
LOCAL_ALBERT_PORT = int(os.environ.get("LOCAL_ALBERT_PORT", "18090"))  # Fixed: use free port 18090 instead of conflicted 8080
LOCAL_ALBERT_SCHEME = os.environ.get("LOCAL_ALBERT_SCHEME", "http")

# --- mTLS toggle for proxy→Albert (env ALBERT_MTLS_CA) ---
# If ALBERT_MTLS_CA is set (path to CA bundle), proxy should present client cert and Albert will require it.
# If not set, warn that proxy→Albert is unauthenticated (see albert_server.py _get_mtls_ca, SECURITY.md).
ALBERT_MTLS_CA = os.environ.get("ALBERT_MTLS_CA", "").strip()
ALBERT_MTLS_CERT = os.environ.get("ALBERT_MTLS_CERT", "").strip()
ALBERT_MTLS_KEY = os.environ.get("ALBERT_MTLS_KEY", "").strip()


def _safe_request_path(path: str) -> str:
    """Return a bounded request path without query-string secrets."""
    return str(path or "/").split("?", 1)[0][:512]

def _log_mtls_status():
    ca = ALBERT_MTLS_CA or os.environ.get("ALBERT_MTLS_CA", "").strip()
    if ca:
        if not os.path.exists(ca):
            try:
                ctx.log.warn(f"mTLS enabled but ALBERT_MTLS_CA={ca} not found — client cert verification will fail")
            except Exception:
                pass
        else:
            try:
                ctx.log.info(f"mTLS enabled — proxy→Albert requires client cert (CA={ca})")
            except Exception:
                pass
        if LOCAL_ALBERT_SCHEME != "https":
            try:
                ctx.log.warn(f"ALBERT_MTLS_CA set but LOCAL_ALBERT_SCHEME={LOCAL_ALBERT_SCHEME} != https — mTLS requires https for TLS client cert")
            except Exception:
                pass
        if ALBERT_MTLS_CERT or ALBERT_MTLS_KEY:
            try:
                ctx.log.info(f"mTLS client cert: cert={ALBERT_MTLS_CERT or 'default'} key={'set' if ALBERT_MTLS_KEY else 'default'}")
            except Exception:
                pass
    else:
        try:
            ctx.log.warn("ALBERT_MTLS_CA not set — proxy→Albert mTLS disabled (unauthenticated). Set ALBERT_MTLS_CA to a CA bundle to require client cert.")
        except Exception:
            pass

# Log at import time (visible in mitmproxy startup)
try:
    _log_mtls_status()
except Exception:
    pass

class FirmwareRestoreProxy:
    def __init__(self):
        self.request_count = 0

    def load(self, loader):
        # Called when addon is loaded — log mTLS status for visibility
        try:
            _log_mtls_status()
        except Exception:
            pass
        # If mTLS CA is set, ensure mitmproxy will use client certs for upstream (proxy→Albert)
        ca = os.environ.get("ALBERT_MTLS_CA", "").strip()
        cert = os.environ.get("ALBERT_MTLS_CERT", "").strip()
        key = os.environ.get("ALBERT_MTLS_KEY", "").strip()
        if ca and (cert or key):
            try:
                # mitmproxy 11+ expects client_certs to be a DIRECTORY containing cert+key,
                # not a file. Create/copy into a temp dir when cert+key are files.
                import pathlib as _pl
                if cert and key and os.path.exists(cert) and os.path.exists(key):
                    cert_p = _pl.Path(cert)
                    # if cert is already a directory, use directly
                    if cert_p.is_dir():
                        ctx.options.client_certs = str(cert_p)
                        ctx.log.info(f"mTLS client_certs set to dir {cert_p}")
                    else:
                        # cert is a file — mitmproxy bug: file silently fails auth. Prepare dir.
                        try:
                            import shutil
                            d = _pl.Path("/tmp/mitmproxy_client_certs")
                            d.mkdir(parents=True, exist_ok=True)
                            # mitmproxy looks for cert.pem / key.pem or combined; copy as client.pem
                            # To maximize compat, create both cert.pem and key.pem plus combined client.pem
                            try:
                                (d / "cert.pem").write_bytes(_pl.Path(cert).read_bytes())
                                (d / "key.pem").write_bytes(_pl.Path(key).read_bytes())
                                # also combined for older mitmproxy
                                combined = _pl.Path(cert).read_bytes() + b"\n" + _pl.Path(key).read_bytes()
                                (d / "client.pem").write_bytes(combined)
                                ctx.options.client_certs = str(d)
                                ctx.log.info(f"mTLS client_certs dir prepared {d} (from {cert}+{key})")
                            except Exception as e2:
                                ctx.log.error(f"mTLS client_certs dir prepare failed for {cert}: {e2} — not setting fallback (file mode silently fails)")
                        except Exception as e2:
                            ctx.log.error(f"mTLS client_certs dir prep failed {cert}: {e2} — not setting client_certs")
                elif cert and os.path.exists(cert):
                    ctx.log.info(f"mTLS client cert {cert} will be used for upstream")
            except Exception as e:
                ctx.log.warn(f"Failed to set mTLS client_certs: {e}")

    def request(self, flow: http.HTTPFlow) -> None:
        self.request_count += 1
        # mitmproxy 10+ : pretty_host is deprecated, use pretty_url or request.host with authority handling.
        # Use flow.request.pretty_host if available, fallback to host header.
        try:
            host = flow.request.pretty_host
        except AttributeError:
            host = flow.request.host
        # Also check authority
        sni = flow.request.headers.get("Host", host)

        # Redirect ONLY Albert activation traffic to local server
        if host in ALBERT_HOSTS:
            ctx.log.info(f"Intercepted Albert request to {host}: {_safe_request_path(flow.request.path)}")
            # Preserve original host for logging on server side
            flow.request.headers["X-Forwarded-Host"] = host
            flow.request.headers["X-Forwarded-Proto"] = flow.request.scheme
            flow.request.headers["X-Forwarded-By"] = "firmware_restore_proxy"
            # mTLS: if ALBERT_MTLS_CA is set, forward client cert indicator so Albert can verify
            # Proxy presents ALBERT_MTLS_CERT/KEY on TLS handshake; also set header for app-layer verification
            try:
                ca = os.environ.get("ALBERT_MTLS_CA", "").strip()
                if ca:
                    cert_path = os.environ.get("ALBERT_MTLS_CERT", "").strip()
                    token = os.environ.get("ALBERT_MTLS_TOKEN", "").strip()
                    # Prefer shared-secret token if configured (stronger than bare header)
                    if token:
                        flow.request.headers["X-MTLS-Token"] = token
                    if cert_path and os.path.exists(cert_path):
                        # Forward actual PEM (not just "present") so Albert can verify length/PEM vs spoofable string
                        try:
                            pem = pathlib.Path(cert_path).read_text().strip()
                            # mitmproxy will have performed TLS client auth; also forward PEM for app-layer check
                            if "-----BEGIN" in pem and len(pem) > 100:
                                flow.request.headers["X-Client-Cert"] = pem[:8000]
                            else:
                                flow.request.headers["X-Client-Cert"] = "present"
                        except Exception:
                            flow.request.headers["X-Client-Cert"] = "present"
                    else:
                        flow.request.headers["X-Client-Cert"] = "mtls"
            except Exception:
                pass
            # Rewrite to local
            flow.request.host = LOCAL_ALBERT_HOST
            flow.request.port = LOCAL_ALBERT_PORT
            flow.request.scheme = LOCAL_ALBERT_SCHEME
            ctx.log.info(f"Redirected to local Albert host={flow.request.host} port={flow.request.port} path={_safe_request_path(flow.request.path)}")
        elif host in TSS_HOSTS:
            ctx.log.warn(f"TSS request to {host} intercepted but TSS local handling not implemented - forwarding to Apple")
            # Do NOT redirect; let it pass through to Apple

        # Log all firmware restore related requests for debugging
        if any(keyword in flow.request.path.lower() for keyword in ["restore", "firmware", "ipsw", "tss", "fdr", "activation", "albert", "drmhandshake"]):
            ctx.log.info(f"Firmware trace: {flow.request.method} host={host} path={_safe_request_path(flow.request.path)}")
            for key, value in flow.request.headers.items():
                if key.lower() in ["user-agent", "content-type", "host", "x-forwarded-host"]:
                    ctx.log.debug(f"  {key}: {value}")

    def response(self, flow: http.HTTPFlow) -> None:
        try:
            host = flow.request.pretty_host
        except AttributeError:
            host = flow.request.host
        fwd = flow.request.headers.get("X-Forwarded-Host", "")
        effective_host = fwd if fwd in ALBERT_HOSTS else host
        if effective_host in ALBERT_HOSTS or host in LOGGING_KEYWORDS_HOSTS or fwd in LOGGING_KEYWORDS_HOSTS:
            ctx.log.info(f"Response from {effective_host} ({host}): {flow.response.status_code}")
            for key, value in flow.response.headers.items():
                if key.lower() in ["content-type", "ars", "cache-control"]:
                    ctx.log.debug(f"  {key}: {value}")
            if "activation" in flow.request.path.lower() or "drmhandshake" in flow.request.path.lower():
                ctx.log.debug("  Activation response body suppressed for security")

addons = [FirmwareRestoreProxy()]
