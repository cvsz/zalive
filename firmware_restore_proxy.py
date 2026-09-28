# Firmware Restore Proxy Configuration - FIXED
# Use with mitmproxy to intercept and redirect iOS firmware restore traffic
# Installation: pip install mitmproxy
# Usage: mitmproxy -s firmware_restore_proxy.py --set block_global=false
#        or mitmweb -s firmware_restore_proxy.py --set block_global=false
from mitmproxy import http, ctx
import os

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

class FirmwareRestoreProxy:
    def __init__(self):
        self.request_count = 0

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
            ctx.log.info(f"Intercepted Albert request to {host}: {flow.request.path}")
            # Preserve original host for logging on server side
            flow.request.headers["X-Forwarded-Host"] = host
            flow.request.headers["X-Forwarded-Proto"] = flow.request.scheme
            flow.request.headers["X-Forwarded-By"] = "firmware_restore_proxy"
            # Rewrite to local
            flow.request.host = LOCAL_ALBERT_HOST
            flow.request.port = LOCAL_ALBERT_PORT
            flow.request.scheme = LOCAL_ALBERT_SCHEME
            ctx.log.info(f"Redirected to local Albert: {flow.request.scheme}://{flow.request.host}:{flow.request.port}{flow.request.path}")
        elif host in TSS_HOSTS:
            ctx.log.warn(f"TSS request to {host} intercepted but TSS local handling not implemented - forwarding to Apple")
            # Do NOT redirect; let it pass through to Apple

        # Log all firmware restore related requests for debugging
        if any(keyword in flow.request.path.lower() for keyword in ["restore", "firmware", "ipsw", "tss", "fdr", "activation", "albert", "drmhandshake"]):
            ctx.log.info(f"Firmware trace: {flow.request.method} {flow.request.url}")
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
                try:
                    body_preview = flow.response.text[:500] if flow.response.text else "empty"
                    ctx.log.debug(f"  Body preview: {body_preview}")
                except:
                    ctx.log.debug("  Body: [binary/unreadable]")

addons = [FirmwareRestoreProxy()]
