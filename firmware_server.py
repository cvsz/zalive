#!/usr/bin/env python3
"""
Local Firmware/Update Server for iOS devices.
Serves IPSW components, BuildManifest.plist, and implements TSS endpoint for SHSH signing.
"""
import os
import sys
import plistlib
import base64
import hashlib
import hmac
import ipaddress
import uuid
import logging
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from flask import Flask, request, Response, send_file, abort
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography import x509
from cryptography.x509.oid import NameOID

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

IPSW_DIR = Path(os.environ.get("IPSW_DIR", "./firmware"))
BUILD_MANIFEST_PATH = IPSW_DIR / "BuildManifest.plist"
RESTORE_PLIST_PATH = IPSW_DIR / "Restore.plist"

app = Flask(__name__)

FAIRPLAY_KEY_PATH = os.environ.get("FAIRPLAY_KEY_PATH", "certs/fairplay.key")
FAIRPLAY_CERT_PATH = os.environ.get("FAIRPLAY_CERT_PATH", "certs/fairplay.crt")

# Bind address *inside* the process. This is deliberately separate from
# ALBERT_BIND_ADDRESS, which controls the host side of a Docker port publish
# and must not be reused here: binding to loopback inside a container would
# make the published port unreachable. In Docker, host-side publishing is the
# access control boundary (compose defaults it to 127.0.0.1). When running the
# server directly on a host, 127.0.0.1 is the safe default.
DEFAULT_BIND_HOST = "127.0.0.1" if os.environ.get("ALBERT_IN_DOCKER") != "1" else "0.0.0.0"
BIND_HOST = os.environ.get("FIRMWARE_SERVER_BIND", DEFAULT_BIND_HOST).strip() or DEFAULT_BIND_HOST


def _is_loopback_host(host):
    value = str(host or "").strip().lower()
    if value in ("localhost", "localhost.localdomain"):
        return True
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _public_bind_host():
    if os.environ.get("ALBERT_IN_DOCKER") == "1":
        return os.environ.get("ALBERT_BIND_ADDRESS", "127.0.0.1")
    return BIND_HOST


def _require_loopback_publish():
    if not _is_loopback_host(_public_bind_host()):
        raise RuntimeError("Firmware server only supports loopback publishing; put it behind a TLS-authenticated reverse proxy for remote access.")


@app.before_request
def _authorize_firmware_proxy():
    if request.path == "/health":
        return None
    expected = os.environ.get("ALBERT_MTLS_TOKEN", "").strip()
    if expected:
        provided = request.headers.get("X-MTLS-Token", "").strip()
        if not provided or not hmac.compare_digest(provided, expected):
            return abort(401, "proxy authentication required")


_fairplay_private_key = None
_fairplay_cert_chain = None


def load_fairplay_keys():
    global _fairplay_private_key, _fairplay_cert_chain
    key_path = Path(FAIRPLAY_KEY_PATH)
    cert_path = Path(FAIRPLAY_CERT_PATH)
    if key_path.exists():
        _fairplay_private_key = serialization.load_pem_private_key(
            key_path.read_bytes(), password=None
        )
        logger.info(f"Loaded FairPlay private key from {key_path}")
    else:
        logger.warning(f"FairPlay key not found at {key_path}, generating ephemeral")
        _fairplay_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    if cert_path.exists():
        _fairplay_cert_chain = cert_path.read_bytes()
        logger.info(f"Loaded FairPlay cert chain from {cert_path}")
    else:
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."),
            x509.NameAttribute(NameOID.COMMON_NAME, "Apple iPhone Device CA"),
        ])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(
            _fairplay_private_key.public_key()
        ).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=1825)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).sign(_fairplay_private_key, hashes.SHA256())
        _fairplay_cert_chain = cert.public_bytes(serialization.Encoding.PEM)
        logger.info("Generated ephemeral FairPlay CA cert")


def get_fairplay_key():
    if _fairplay_private_key is None:
        load_fairplay_keys()
    return _fairplay_private_key


def get_fairplay_cert_chain():
    if _fairplay_cert_chain is None:
        load_fairplay_keys()
    return _fairplay_cert_chain


@dataclass
class IPSWComponent:
    name: str
    path: str
    digest: bytes
    info: Dict[str, Any]
    trusted: bool = False


class BuildManifestParser:
    def __init__(self, manifest_path: Path):
        self.manifest_path = manifest_path
        self.data = None
        self.components: Dict[str, IPSWComponent] = {}
        self.build_identities: List[Dict] = []
        self._parse()

    def _parse(self):
        if not self.manifest_path.exists():
            logger.error(f"BuildManifest not found: {self.manifest_path}")
            return
        with open(self.manifest_path, "rb") as f:
            self.data = plistlib.load(f)

        self.build_identities = self.data.get("BuildIdentities", [])
        if self.build_identities:
            bi = self.build_identities[0]
            manifest = bi.get("Manifest", {})
            for comp_name, comp_data in manifest.items():
                if isinstance(comp_data, dict):
                    info = comp_data.get("Info", {})
                    digest_b64 = comp_data.get("Digest")
                    if isinstance(digest_b64, bytes):
                        digest = digest_b64
                    elif digest_b64:
                        # Fix base64 padding
                        padding_needed = 4 - (len(digest_b64) % 4)
                        if padding_needed != 4:
                            digest_b64 += "=" * padding_needed
                        digest = base64.b64decode(digest_b64)
                    else:
                        digest = None
                    path = info.get("Path", "")
                    trusted = comp_data.get("Trusted", False)
                    self.components[comp_name] = IPSWComponent(
                        name=comp_name,
                        path=path,
                        digest=digest,
                        info=info,
                        trusted=trusted
                    )
        logger.info(f"Parsed {len(self.components)} components from BuildManifest")

    def get_component(self, name: str) -> Optional[IPSWComponent]:
        return self.components.get(name)

    def get_component_by_path(self, path: str) -> Optional[IPSWComponent]:
        for comp in self.components.values():
            if comp.path == path:
                return comp
        return None

    def get_all_components(self) -> List[IPSWComponent]:
        return list(self.components.values())


manifest_parser = BuildManifestParser(BUILD_MANIFEST_PATH)


def sign_cms(data: bytes, key, cert_chain: bytes) -> bytes:
    """Sign data as CMS/PKCS#7 detached signature (Apple APTicket format)."""
    certs = [x509.load_pem_x509_certificate(c) for c in cert_chain.split(b"-----END CERTIFICATE-----") if b"-----BEGIN CERTIFICATE-----" in c]
    if not certs:
        cert = x509.load_pem_x509_certificate(cert_chain)
        certs = [cert]
    # SHA-1 is mandated by Apple's APTicket/CMS format; the signature is
    # verified against Apple's published certificate, so this is a protocol
    # requirement rather than a weak-hash choice of our own.
    signed = pkcs7.PKCS7SignatureBuilder().set_data(data).add_signer(
        certs[0], key, hashes.SHA1()  # nosec B303 - Apple APTicket format requires SHA-1
    ).sign(serialization.Encoding.DER, [])
    return signed


def generate_apticket(request_params: Dict[str, str], component: IPSWComponent) -> bytes:
    """Generate APTicket (SHSH blob) for a component."""
    ecid = int(request_params.get("deviceid", "0"), 16) if request_params.get("deviceid") else 0
    build_id = request_params.get("buildid", "")
    board_id = int(request_params.get("boardid", "0"), 16) if request_params.get("boardid") else 0
    chip_id = int(request_params.get("chipid", "0"), 16) if request_params.get("chipid") else 0
    ap_security_domain = int(request_params.get("apsecuritydomain", "1"))
    ap_production_mode = request_params.get("approductionmode", "1") == "1"
    ap_raw_security_mode = request_params.get("aprawsecuritymode", "0") == "1"
    unique_build_id = request_params.get("uniquebuildid", "")
    nonce_b64 = request_params.get("nonce", "")
    nonce = base64.b64decode(nonce_b64) if nonce_b64 else os.urandom(32)

    apticket = {
        "ApTicket": {
            "ApECID": ecid,
            "ApNonce": nonce,
            "ApProductionMode": ap_production_mode,
            "ApSecurityDomain": ap_security_domain,
            "ApTicket": b"",  # Will be filled after signing
            "BuildIdentity": {
                "Ap,ChipID": chip_id,
                "Ap,BoardID": board_id,
                "Ap,SecurityDomain": ap_security_domain,
                "UniqueBuildID": unique_build_id,
            },
            "Component": {
                "Name": component.name,
                "Digest": component.digest,
                "Path": component.path,
            }
        }
    }

    apticket_plist = plistlib.dumps(apticket)
    key = get_fairplay_key()
    cert_chain = get_fairplay_cert_chain()
    signature = sign_cms(apticket_plist, key, cert_chain)

    apticket["ApTicket"]["ApTicket"] = signature
    return plistlib.dumps(apticket)


@app.route("/BuildManifest.plist")
def serve_build_manifest():
    if not BUILD_MANIFEST_PATH.exists():
        return abort(404, "BuildManifest.plist not found")
    return send_file(BUILD_MANIFEST_PATH, mimetype="application/x-plist")


@app.route("/Restore.plist")
def serve_restore_plist():
    if not RESTORE_PLIST_PATH.exists():
        return abort(404, "Restore.plist not found")
    return send_file(RESTORE_PLIST_PATH, mimetype="application/x-plist")


@app.route("/components/<path:component_path>")
def serve_component(component_path: str):
    # Reject anything that is not a plain relative manifest entry before the
    # value is ever joined onto IPSW_DIR. The manifest lookup below is an
    # exact match and would already reject it, but rejecting traversal syntax
    # up front keeps a hostile path from reaching the filesystem at all.
    relative = Path(component_path)
    if relative.is_absolute() or ".." in relative.parts or component_path.startswith("/"):
        return abort(400, "Invalid component path")

    comp = manifest_parser.get_component_by_path(component_path)
    if not comp:
        return abort(404, f"Component not found: {component_path}")

    # Join from the manifest entry, not from the request. The manifest ships
    # with the firmware and its paths are trusted, so no attacker-controlled
    # string reaches the filesystem at all. resolve() plus the containment
    # check then guards against a symlink inside the mounted tree.
    try:
        file_path = (IPSW_DIR / comp.path).resolve()
        root = IPSW_DIR.resolve()
    except OSError:
        return abort(404, f"File not found: {component_path}")
    if root != file_path and root not in file_path.parents:
        return abort(403, "Component path escapes the firmware directory")
    if not file_path.is_file():
        return abort(404, f"File not found: {component_path}")

    return send_file(file_path, as_attachment=False)


@app.route("/TSS/controller")
def tss_controller():
    action = request.args.get("action")
    if action != "2":
        return abort(400, "Only action=2 (SHSH request) supported")

    component_name = request.args.get("component", "OS")
    logger.info("TSS request action=%s query_fields=%d", action, len(request.args))
    comp = manifest_parser.get_component(component_name)
    if not comp:
        return abort(404, f"Component {component_name} not in manifest")

    try:
        apticket_data = generate_apticket(dict(request.args), comp)
        return Response(apticket_data, mimetype="application/x-plist")
    except Exception as e:
        logger.exception("TSS signing failed")
        return abort(500, "Signing failed")


@app.route("/firmware/list")
def list_firmware():
    components = []
    for comp in manifest_parser.get_all_components():
        components.append({
            "name": comp.name,
            "path": comp.path,
            "digest": base64.b64encode(comp.digest).decode() if comp.digest else None,
            "size": (IPSW_DIR / comp.path).stat().st_size if (IPSW_DIR / comp.path).exists() else 0,
            "trusted": comp.trusted,
            "info": comp.info
        })
    return {"components": components, "count": len(components)}


@app.route("/health")
def health():
    return {"status": "ok", "service": "firmware-server", "components": len(manifest_parser.components)}


if __name__ == "__main__":
    port = int(os.environ.get("FIRMWARE_SERVER_PORT", "18091"))
    try:
        _require_loopback_publish()
    except RuntimeError as exc:
        logger.error("%s", exc)
        sys.exit(2)
    token = os.environ.get("ALBERT_MTLS_TOKEN", "").strip()
    if token and len(token) < 32:
        logger.error("ALBERT_MTLS_TOKEN must contain at least 32 characters.")
        sys.exit(2)
    if os.environ.get("ALBERT_IN_DOCKER") == "1" and not token:
        logger.error("Compose firmware service requires ALBERT_MTLS_TOKEN with at least 32 characters.")
        sys.exit(2)
    load_fairplay_keys()
    logger.info(f"Starting firmware server on {BIND_HOST}:{port}")
    app.run(host=BIND_HOST, port=port, threaded=True)