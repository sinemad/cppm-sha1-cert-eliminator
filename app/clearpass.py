"""Shared ClearPass certificate logic used by both the CLI and web API."""

import base64
from dataclasses import dataclass
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from pyclearpass import ApiPlatformCertificates, ClearPassAPILogin


SHA1_ALGORITHM_STRINGS = (
    "sha1",
    "sha-1",
    "sha1withrsaencryption",
    "ecdsa-with-sha1",
    "dsawithsha1",
    "id-dsa-with-sha1",
)


@dataclass
class ClearPassConfig:
    server: str
    api_token: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    verify_ssl: bool = True


def make_login(config: ClearPassConfig) -> ClearPassAPILogin:
    if config.api_token:
        return ClearPassAPILogin(
            server=config.server,
            api_token=config.api_token,
            verify_ssl=config.verify_ssl,
        )
    if config.client_id and config.client_secret:
        return ClearPassAPILogin(
            server=config.server,
            client_id=config.client_id,
            client_secret=config.client_secret,
            verify_ssl=config.verify_ssl,
        )
    raise ValueError("Provide api_token or both client_id and client_secret.")


def is_sha1_by_fields(cert_entry: dict) -> bool:
    for field in ("subject_hash_alg", "signature_algorithm", "hash_algorithm", "algorithm"):
        value = cert_entry.get(field, "")
        if value and any(s in value.lower() for s in SHA1_ALGORITHM_STRINGS):
            return True
    return False


def is_sha1_by_pem(pem_data: str) -> Optional[bool]:
    """Return True if SHA-1 signed, False if not, None if unparseable."""
    try:
        pem_bytes = pem_data.encode() if isinstance(pem_data, str) else pem_data
        if b"-----BEGIN" not in pem_bytes:
            try:
                der_bytes = base64.b64decode(pem_data)
                cert = x509.load_der_x509_certificate(der_bytes, default_backend())
            except Exception:
                return None
        else:
            cert = x509.load_pem_x509_certificate(pem_bytes, default_backend())
        sig_hash = cert.signature_hash_algorithm
        return sig_hash is not None and isinstance(sig_hash, hashes.SHA1)
    except Exception:
        return None


def fetch_all_trust_list(login: ClearPassAPILogin) -> list[dict]:
    all_entries: list[dict] = []
    offset = 0
    page_size = 100

    while True:
        response = ApiPlatformCertificates.get_cert_trust_list(
            login, limit=page_size, offset=offset, calculate_count=True
        )
        if not isinstance(response, dict):
            break
        items = response.get("items", [])
        all_entries.extend(items)
        total = response.get("count", len(items))
        offset += len(items)
        if not items or offset >= total:
            break

    return all_entries


def identify_sha1_certs(login: ClearPassAPILogin, entries: list[dict]) -> list[dict]:
    sha1_entries = []

    for entry in entries:
        cert_id = entry.get("id")
        detected_by = None

        if is_sha1_by_fields(entry):
            detected_by = "metadata"
        else:
            pem_field = entry.get("cert_file") or entry.get("pem") or entry.get("certificate")
            if not pem_field and cert_id:
                try:
                    detail = ApiPlatformCertificates.get_cert_trust_list_by_cert_trust_list_id(
                        login, cert_trust_list_id=cert_id
                    )
                    if isinstance(detail, dict):
                        pem_field = (
                            detail.get("cert_file")
                            or detail.get("pem")
                            or detail.get("certificate")
                        )
                        entry = {**entry, **detail}
                except Exception:
                    pass

            if pem_field:
                result = is_sha1_by_pem(pem_field)
                if result is True:
                    detected_by = "cert parsing"

        if detected_by:
            sha1_entries.append({**entry, "_detected_by": detected_by})

    return sha1_entries


def remove_cert(login: ClearPassAPILogin, cert_id: Any) -> None:
    """Delete a trust list entry. Raises on failure."""
    ApiPlatformCertificates.delete_cert_trust_list_by_cert_trust_list_id(
        login, cert_trust_list_id=cert_id
    )


def safe_serialize(entry: dict) -> dict:
    """Convert all values to JSON-safe types."""
    return {
        k: (str(v) if not isinstance(v, (str, int, float, bool, type(None))) else v)
        for k, v in entry.items()
    }
