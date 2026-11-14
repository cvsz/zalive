#!/usr/bin/env python3
"""
Generate an Apple-style FairPlay private key + self-signed CA certificate.

Produces RSA-2048 key material matching the format Albert Server expects
(certs/fairplay.key + certs/fairplay.crt, 0600 permissions). Subject/issuer
follow Apple's device-CA naming ("Apple Inc." / "iPhone" / "Apple iPhone
Device CA"). Validity is 5 years (1825 days) by default.

SHA-256 is used for the certificate signature by default; pass --sha1 only
when targeting Apple's legacy ARS handshake (SHA-1 mandated by the protocol,
not a general-purpose hash choice).

Usage:
    python3 scripts/generate_apple_fairplay_key.py --force
    python3 scripts/generate_apple_fairplay_key.py --out certs --name fairplay --days 1825
"""
from __future__ import annotations

import argparse
import datetime as _dt
import logging
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("generate_apple_fairplay_key")

DEFAULT_OUT_DIR = "certs"
DEFAULT_NAME = "fairplay"
DEFAULT_DAYS = 1825  # 5 years
DEFAULT_KEY_SIZE = 2048
DEFAULT_HASH = hashes.SHA256()


def _subject_issuer() -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "iPhone"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Apple iPhone Device CA"),
    ])


def generate_key_pair(key_size: int = DEFAULT_KEY_SIZE) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def build_self_signed_ca(
    key: rsa.RSAPrivateKey,
    days: int = DEFAULT_DAYS,
    hash_algorithm: hashes.HashAlgorithm = DEFAULT_HASH,
) -> x509.Certificate:
    now = _dt.datetime.now(_dt.timezone.utc)
    not_after = now + _dt.timedelta(days=days)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_subject_issuer())
        .issuer_name(_subject_issuer())
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=True,
                crl_sign=True,
                key_agreement=False,
                data_encipherment=False,
                content_commitment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
    )
    return builder.sign(private_key=key, algorithm=hash_algorithm)


def write_key_and_cert(
    key: rsa.RSAPrivateKey,
    cert: x509.Certificate,
    key_path: Path,
    cert_path: Path,
    force: bool = False,
) -> None:
    for path in (key_path, cert_path):
        if path.exists() and not force:
            raise FileExistsError(f"{path} already exists — pass --force to overwrite")

    key_path.parent.mkdir(parents=True, exist_ok=True)

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(key_pem)
    key_path.chmod(0o600)
    logger.info(f"Wrote {key_path} (0600), {len(key_pem)} bytes")

    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    cert_path.write_bytes(cert_pem)
    cert_path.chmod(0o600)
    logger.info(f"Wrote {cert_path} (0600), {len(cert_pem)} bytes")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate Apple-style FairPlay private key + self-signed CA certificate.",
    )
    parser.add_argument("--out", default=DEFAULT_OUT_DIR, help=f"output directory (default: {DEFAULT_OUT_DIR})")
    parser.add_argument("--name", default=DEFAULT_NAME, help=f"base filename (default: {DEFAULT_NAME})")
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS, help=f"validity in days (default: {DEFAULT_DAYS})")
    parser.add_argument(
        "--key-size",
        type=int,
        default=DEFAULT_KEY_SIZE,
        help=f"RSA key size in bits (default: {DEFAULT_KEY_SIZE})",
    )
    parser.add_argument(
        "--sha1",
        action="store_true",
        help="use SHA-1 for certificate signature (Apple ARS protocol mandate; not for general use)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite existing key/cert files",
    )
    args = parser.parse_args()

    hash_algorithm = hashes.SHA1() if args.sha1 else DEFAULT_HASH

    key_path = Path(args.out) / f"{args.name}.key"
    cert_path = Path(args.out) / f"{args.name}.crt"

    try:
        key = generate_key_pair(args.key_size)
        cert = build_self_signed_ca(key, days=args.days, hash_algorithm=hash_algorithm)
        write_key_and_cert(key, cert, key_path, cert_path, force=args.force)

        not_after = cert.not_valid_after_utc
        logger.info(
            f"Apple-style FairPlay CA generated: CN={_subject_issuer().get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}, "
            f"NotAfter={not_after.date()} ({args.days} days), hash={'SHA-1' if args.sha1 else 'SHA-256'}"
        )
        return 0
    except Exception as exc:
        logger.error(f"Failed to generate Apple-style FairPlay key material: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
