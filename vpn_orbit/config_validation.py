"""Validation delegates to its subprocess owner; live probes always supply the supervisor adapter.

Standalone synthesis defaults are timeout-bounded, but do not promise recovery after caller SIGKILL.
"""
import re
import ssl
import subprocess
import time

from .phase1 import UnsupportedProfile
from .probe_commands import Commands


def validate_pem(certificate: str, *, commands: Commands | None = None) -> None:
    pem = certificate.strip()
    pattern = re.compile(
        r"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+\s+-----END CERTIFICATE-----"
    )
    certificates = list(pattern.finditer(pem))
    gaps = [
        pem[start:end]
        for start, end in zip(
            [0, *(match.end() for match in certificates)],
            [*(match.start() for match in certificates), len(pem)],
        )
    ]
    if not certificates or any(gap.strip() for gap in gaps):
        raise UnsupportedProfile("ambiguous CA PEM")
    try:
        owner = commands or Commands(time.monotonic() + 2)
        for match in certificates:
            certificate_pem = match.group()
            ssl.PEM_cert_to_DER_cert(certificate_pem)
            owner.openssl(["x509", "-noout"], certificate_pem.encode(), 2)
    except (ValueError, OSError, TimeoutError, subprocess.SubprocessError) as exc:
        raise UnsupportedProfile("invalid CA certificate") from exc


def spki_match(cert_pem: bytes, key_pem: bytes, timeout_s: float = 5,
               *, commands: Commands | None = None) -> tuple[bool, str]:
    deadline = time.monotonic() + timeout_s
    owner = commands or Commands(deadline)
    try:
        cert_pub = owner.openssl(["x509", "-pubkey", "-noout"], cert_pem, max(0.001, deadline - time.monotonic()))
        pub_der = owner.openssl(["pkey", "-pubin", "-outform", "DER"], cert_pub, max(0.001, deadline - time.monotonic()))
        key_der = owner.openssl(["pkey", "-pubout", "-outform", "DER"], key_pem, max(0.001, deadline - time.monotonic()))
    except (OSError, TimeoutError, subprocess.SubprocessError):
        return False, "SPKI comparison failed"
    return pub_der == key_der, ""


def quote_word(value: str) -> str:
    if not isinstance(value, str) or any(c in value for c in "\n\r\x00\\"):
        raise UnsupportedProfile("invalid directive value")
    return '"' + value.replace('"', '\\"') + '"' if re.search(r'[\s"]', value) else value
