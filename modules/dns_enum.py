"""Basic DNS enumeration: A/AAAA/MX/NS/TXT + common subdomain wordlist."""

from __future__ import annotations

import concurrent.futures
import socket
from typing import Any

try:
    import dns.resolver  # type: ignore

    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

DEFAULT_SUBS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "dns",
    "vpn", "api", "dev", "staging", "test", "admin", "portal", "app",
    "cdn", "blog", "shop", "m", "mobile", "remote", "git", "ci", "status",
]


class DNSEnumerator:
    def __init__(self, domain: str, wordlist: str | None = None, timeout: float = 2.0):
        self.domain = domain.strip().lower().rstrip(".")
        self.wordlist = wordlist
        self.timeout = timeout

    def _resolve_socket(self, host: str) -> list[str]:
        try:
            infos = socket.getaddrinfo(host, None)
            return sorted({i[4][0] for i in infos})
        except socket.gaierror:
            return []

    def _record_types(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": []}
        if not HAS_DNSPYTHON:
            out["A"] = self._resolve_socket(self.domain)
            return out

        resolver = dns.resolver.Resolver()
        resolver.lifetime = self.timeout
        for rtype in out:
            try:
                answers = resolver.resolve(self.domain, rtype)
                out[rtype] = [r.to_text() for r in answers]
            except Exception:
                pass
        return out

    def _load_subs(self) -> list[str]:
        if self.wordlist:
            try:
                with open(self.wordlist, encoding="utf-8", errors="ignore") as f:
                    return [line.strip() for line in f if line.strip() and not line.startswith("#")]
            except OSError:
                pass
        return list(DEFAULT_SUBS)

    def enumerate(self) -> dict[str, Any]:
        records = self._record_types()
        subs = self._load_subs()
        found: list[dict[str, Any]] = []

        def check(sub: str) -> dict[str, Any] | None:
            host = f"{sub}.{self.domain}"
            ips = self._resolve_socket(host)
            if ips:
                return {"host": host, "ips": ips}
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            for result in pool.map(check, subs):
                if result:
                    found.append(result)

        return {
            "module": "dns_enum",
            "domain": self.domain,
            "records": records,
            "subdomains": found,
            "subdomain_count": len(found),
            "dnspython": HAS_DNSPYTHON,
        }
