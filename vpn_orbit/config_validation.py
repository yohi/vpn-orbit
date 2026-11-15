import re
import ssl
import subprocess
import time

from .phase1 import UnsupportedProfile


def validate_pem(certificate: str) -> None:
    pem = certificate.strip()
    if not re.fullmatch(r"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+\s+-----END CERTIFICATE-----", pem):
        raise UnsupportedProfile("ambiguous CA PEM")
    try:
        ssl.PEM_cert_to_DER_cert(pem)
        subprocess.run(["openssl", "x509", "-noout"], input=pem.encode(),
                       capture_output=True, check=True, timeout=2,
                       env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        raise UnsupportedProfile("invalid CA certificate") from exc


def spki_match(cert_pem: bytes, key_pem: bytes, timeout_s: float = 5) -> tuple[bool, str]:
    deadline = time.monotonic() + timeout_s
    try:
        cert_pub = subprocess.run(["openssl", "x509", "-pubkey", "-noout"], input=cert_pem,
            capture_output=True, check=True, timeout=max(0.001, deadline - time.monotonic()),
            env={"PATH": "/usr/bin:/bin", "LANG": "C"}).stdout
        pub_der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"], input=cert_pub,
            capture_output=True, check=True, timeout=max(0.001, deadline - time.monotonic()),
            env={"PATH": "/usr/bin:/bin", "LANG": "C"}).stdout
        key_der = subprocess.run(["openssl", "pkey", "-pubout", "-outform", "DER"], input=key_pem,
            capture_output=True, check=True, timeout=max(0.001, deadline - time.monotonic()),
            env={"PATH": "/usr/bin:/bin", "LANG": "C"}).stdout
    except (OSError, subprocess.SubprocessError):
        return False, "SPKI comparison failed"
    return pub_der == key_der, ""


def quote_word(value: str) -> str:
    if not isinstance(value, str) or any(c in value for c in "\n\r\x00\\"):
        raise UnsupportedProfile("invalid directive value")
    return '"' + value.replace('"', '\\"') + '"' if re.search(r'[\s"]', value) else value
