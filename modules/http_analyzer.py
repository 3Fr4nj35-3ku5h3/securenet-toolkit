"""HTTP security headers analysis."""

from __future__ import annotations

from typing import Any
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


SECURITY_HEADERS = {
    "strict-transport-security": {"weight": 20, "hint": "Enable HSTS"},
    "content-security-policy": {"weight": 20, "hint": "Add CSP"},
    "x-content-type-options": {"weight": 15, "hint": "Set nosniff"},
    "x-frame-options": {"weight": 15, "hint": "DENY or SAMEORIGIN"},
    "referrer-policy": {"weight": 10, "hint": "Set a strict referrer policy"},
    "permissions-policy": {"weight": 10, "hint": "Restrict powerful features"},
    "x-xss-protection": {"weight": 5, "hint": "Legacy; prefer CSP"},
    "cross-origin-opener-policy": {"weight": 5, "hint": "Consider COOP"},
}


class HTTPAnalyzer:
    def __init__(self, url: str, timeout: float = 8.0):
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        self.url = url
        self.timeout = timeout

    def analyze_headers(self) -> dict[str, Any]:
        req = Request(self.url, headers={"User-Agent": "SecureNet-Toolkit/1.1"})
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                status = resp.status
        except HTTPError as e:
            headers = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
            status = e.code
        except URLError as e:
            return {
                "module": "http_analyzer",
                "url": self.url,
                "error": str(e.reason if hasattr(e, "reason") else e),
                "score": 0,
            }

        present = []
        missing = []
        score = 0
        for name, meta in SECURITY_HEADERS.items():
            if name in headers:
                present.append({"header": name, "value": headers[name][:200]})
                score += meta["weight"]
            else:
                missing.append({"header": name, "hint": meta["hint"]})

        return {
            "module": "http_analyzer",
            "url": self.url,
            "status": status,
            "score": min(100, score),
            "present": present,
            "missing": missing,
            "server": headers.get("server"),
        }
