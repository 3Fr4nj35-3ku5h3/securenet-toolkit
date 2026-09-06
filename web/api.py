"""
SecureNet Console API — authorized network assessment helpers.

  uvicorn web.api:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import ipaddress
import re
import time
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"

# Import toolkit modules
import sys

sys.path.insert(0, str(ROOT))
from modules.dns_enum import DNSEnumerator
from modules.http_analyzer import HTTPAnalyzer
from modules.port_scanner import PortScanner
from modules.ssl_analyzer import SSLAnalyzer

app = FastAPI(
    title="SecureNet Console",
    description="Authorized network assessment toolkit — port, SSL, HTTP headers, DNS.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simple in-process rate limit: max N jobs per window
_RATE: dict[str, list[float]] = {}
_RATE_WINDOW = 60.0
_RATE_MAX = 12

HOST_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,251}[a-zA-Z0-9])?$")


def _client_key(extra: str = "") -> str:
    return extra or "global"


def _rate_check(key: str = "global") -> None:
    now = time.time()
    bucket = _RATE.setdefault(key, [])
    _RATE[key] = [t for t in bucket if now - t < _RATE_WINDOW]
    if len(_RATE[key]) >= _RATE_MAX:
        raise HTTPException(429, "Rate limit — wait a minute and try again")
    _RATE[key].append(now)


def _normalize_host(target: str) -> str:
    t = target.strip()
    t = re.sub(r"^https?://", "", t, flags=re.I)
    t = t.split("/")[0].split(":")[0].strip().lower()
    if not t or not HOST_RE.match(t) and not _is_ip(t):
        raise HTTPException(400, "Invalid hostname or IP")
    return t


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _reject_dangerous_targets(host: str) -> None:
    """Block obvious local/metadata targets on the public console."""
    blocked_names = {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata",
    }
    if host in blocked_names or host.endswith(".local") or host.endswith(".internal"):
        raise HTTPException(400, "Local/metadata targets are not allowed on the public console")
    if _is_ip(host):
        ip = ipaddress.ip_address(host)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        ):
            raise HTTPException(400, "Private/reserved IPs are not allowed on the public console")


class AuthAck(BaseModel):
    authorized: bool = Field(..., description="Must be true — you confirm authorized testing")


class PortRequest(AuthAck):
    target: str
    port_range: str = Field("common", description="common | top | or limited range e.g. 80-100")
    detect_services: bool = False


class SslRequest(AuthAck):
    target: str


class HttpRequest(AuthAck):
    url: str


class DnsRequest(AuthAck):
    domain: str


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "version": "2.0.0", "product": "SecureNet Console"}


@app.get("/api/modules")
def modules() -> dict[str, Any]:
    return {
        "modules": [
            {
                "id": "ports",
                "name": "Port Scanner",
                "description": "TCP connect scan of common or limited ports with optional banner grab",
            },
            {
                "id": "ssl",
                "name": "SSL/TLS Analyzer",
                "description": "Certificate metadata, expiry, TLS version, basic grade",
            },
            {
                "id": "http",
                "name": "HTTP Security Headers",
                "description": "Score common security headers and list gaps",
            },
            {
                "id": "dns",
                "name": "DNS Enumeration",
                "description": "Core records + small subdomain wordlist resolution",
            },
        ],
        "policy": {
            "authorized_only": True,
            "public_console_blocks": ["private IPs", "localhost", "link-local", "metadata hosts"],
            "port_scan_cap": "common set or ranges ≤ 200 ports",
        },
    }


def _require_auth(authorized: bool) -> None:
    if not authorized:
        raise HTTPException(403, "Confirm authorized testing before running checks")


def _cap_port_range(port_range: str) -> str:
    pr = (port_range or "common").strip().lower()
    if pr in ("common", "top"):
        return "common"
    if "-" in pr:
        a, b = pr.split("-", 1)
        try:
            start, end = int(a), int(b)
        except ValueError:
            raise HTTPException(400, "Invalid port range")
        if end < start:
            start, end = end, start
        if end - start + 1 > 200:
            raise HTTPException(400, "Port range too large for public console (max 200 ports)")
        if start < 1 or end > 65535:
            raise HTTPException(400, "Ports must be 1–65535")
        return f"{start}-{end}"
    # comma list
    try:
        ports = [int(p.strip()) for p in pr.split(",") if p.strip()]
    except ValueError:
        raise HTTPException(400, "Invalid port list")
    if len(ports) > 200:
        raise HTTPException(400, "Max 200 ports")
    return ",".join(str(p) for p in ports)


@app.post("/api/scan/ports")
def scan_ports(req: PortRequest) -> dict[str, Any]:
    _require_auth(req.authorized)
    _rate_check()
    host = _normalize_host(req.target)
    _reject_dangerous_targets(host)
    pr = _cap_port_range(req.port_range)
    result = PortScanner(host, pr, req.detect_services, timeout=0.6, max_workers=60).scan()
    result["policy_note"] = "Authorized use only. Results are advisory."
    return result


@app.post("/api/scan/ssl")
def scan_ssl(req: SslRequest) -> dict[str, Any]:
    _require_auth(req.authorized)
    _rate_check()
    host = _normalize_host(req.target)
    _reject_dangerous_targets(host)
    result = SSLAnalyzer(host).analyze()
    result["policy_note"] = "Authorized use only. Results are advisory."
    return result


@app.post("/api/scan/http")
def scan_http(req: HttpRequest) -> dict[str, Any]:
    _require_auth(req.authorized)
    _rate_check()
    url = req.url.strip()
    if not url:
        raise HTTPException(400, "URL required")
    # Extract host for policy
    host = _normalize_host(url)
    _reject_dangerous_targets(host)
    result = HTTPAnalyzer(url).analyze_headers()
    result["policy_note"] = "Authorized use only. Results are advisory."
    return result


@app.post("/api/scan/dns")
def scan_dns(req: DnsRequest) -> dict[str, Any]:
    _require_auth(req.authorized)
    _rate_check()
    domain = _normalize_host(req.domain)
    _reject_dangerous_targets(domain)
    result = DNSEnumerator(domain).enumerate()
    result["policy_note"] = "Authorized use only. Results are advisory."
    return result


if STATIC.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


@app.get("/")
def index() -> FileResponse:
    path = STATIC / "index.html"
    if not path.exists():
        raise HTTPException(404, "Console UI missing")
    return FileResponse(path)
