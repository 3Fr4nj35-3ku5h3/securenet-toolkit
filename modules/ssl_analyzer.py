"""SSL/TLS certificate and basic configuration check."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any


class SSLAnalyzer:
    def __init__(self, target: str, check_expiry: bool = True, port: int = 443, timeout: float = 5.0):
        self.target = target.replace("https://", "").replace("http://", "").split("/")[0]
        self.check_expiry = check_expiry
        self.port = port
        self.timeout = timeout

    def analyze(self) -> dict[str, Any]:
        ctx = ssl.create_default_context()
        # We still want cert info even if verification fails
        try:
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
        except ssl.SSLCertVerificationError as e:
            # Retry without verification to still extract cert metadata
            ctx2 = ssl._create_unverified_context()
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with ctx2.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
            verification_error = str(e)
        except Exception as e:
            return {
                "module": "ssl_analyzer",
                "target": self.target,
                "error": str(e),
                "grade": "F",
            }
        else:
            verification_error = None

        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        not_after = cert.get("notAfter")
        days_left = None
        if not_after and self.check_expiry:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (exp - datetime.now(timezone.utc)).days
            except ValueError:
                days_left = None

        grade = "A"
        if verification_error:
            grade = "C"
        if days_left is not None and days_left < 0:
            grade = "F"
        elif days_left is not None and days_left < 30:
            grade = "B"

        return {
            "module": "ssl_analyzer",
            "target": self.target,
            "tls_version": version,
            "cipher": cipher[0] if cipher else None,
            "subject_cn": subject.get("commonName"),
            "issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "not_after": not_after,
            "days_until_expiry": days_left,
            "san": cert.get("subjectAltName", []),
            "verification_error": verification_error,
            "grade": grade,
        }
