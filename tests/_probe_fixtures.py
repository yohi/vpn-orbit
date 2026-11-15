import subprocess
from pathlib import Path
from typing import Literal

from vpn_orbit.cloud_probe import RemoteKey, ScreenedCandidate
from vpn_orbit.geoip import GeoDecision
from vpn_orbit.phase1 import Candidate

JsonValue = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]

def _generate_cert_key(tmp: Path, name: str = "test") -> tuple[str, str]:
    key_path, cert_path = tmp / f"{name}.key", tmp / f"{name}.crt"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key_path), "-out", str(cert_path), "-days", "1", "-subj", "/CN=test"],
        capture_output=True, check=True, timeout=5)
    return cert_path.read_text(), key_path.read_text()


def _mismatched_cert_key(tmp: Path) -> tuple[str, str]:
    cert, _ = _generate_cert_key(tmp, "a")
    _, key = _generate_cert_key(tmp, "b")
    return cert, key


def _static_key() -> str:
    return "-----BEGIN OpenVPN Static key V1-----\n" + ("a" * 64 + "\n") * 8 + "-----END OpenVPN Static key V1-----"


def _endpoint(*, ca: str | None = None, cert: str | None = None, key: str | None = None,
              control_wrap: dict[str, JsonValue] | None = None, username: str | None = None,
              password: str | None = None, remote_cert_tls: str = "server", remote_cert_eku: str | None = None,
              server_name: str | None = None, server_name_type: str = "name", data_ciphers: list[str] | None = None,
              fallback: str = "AES-128-CBC", auth: str = "SHA1") -> dict[str, JsonValue]:
    if ca is None:
        ca = (Path(__file__).parent / "fixtures" / "test-ca.pem").read_text()
    tls: dict[str, JsonValue] = {"certificate": [ca]}
    if remote_cert_eku:
        tls["remote_certificate_eku"] = remote_cert_eku
    else:
        tls["remote_certificate_tls"] = remote_cert_tls
    if cert is not None:
        tls["client_certificate"] = [cert]
    if key is not None:
        tls["client_key"] = [key]
    if control_wrap:
        tls["control_wrap"] = control_wrap
    if server_name:
        tls.update(server_name=server_name, server_name_type=server_name_type)
    ciphers: list[JsonValue] = list(data_ciphers or ["AES-256-GCM", "AES-128-GCM"])
    endpoint: dict[str, JsonValue] = {"type": "openvpn-client", "tag": "vpn-gate", "mode": "tls",
        "server": "8.8.8.8", "server_port": 1195, "network": "udp", "tls": tls,
        "data_ciphers": ciphers,
        "data_ciphers_fallback": fallback, "auth": auth, "block_ipv6": True,
        "ping_interval": "10s", "ping_restart": "40s"}
    if username is not None and password is not None:
        endpoint.update(username=username, password=password)
    return endpoint


def _candidate(tmp: Path, ip: str = "8.8.8.8", port: int = 1195,
               protocol: Literal["tcp", "udp"] = "udp") -> ScreenedCandidate:
    ca, _ = _generate_cert_key(tmp)
    profile = (f"client\nproto {protocol}\nremote {ip} {port}\ncipher AES-128-CBC\n"
               f"auth SHA1\nremote-cert-tls server\n<ca>\n{ca}</ca>\n")
    return ScreenedCandidate(Candidate("test", ip, "JP", 1, 1, 1, profile),
        RemoteKey(ip, port, protocol), GeoDecision.TOKYO, 1)
