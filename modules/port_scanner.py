"""TCP port scanner with optional banner grab."""

from __future__ import annotations

import concurrent.futures
import socket
from typing import Any


COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
]


class PortScanner:
    def __init__(
        self,
        target: str,
        port_range: str = "1-1000",
        detect_services: bool = False,
        timeout: float = 0.8,
        max_workers: int = 80,
    ):
        self.target = target
        self.port_range = port_range
        self.detect_services = detect_services
        self.timeout = timeout
        self.max_workers = max_workers

    def _ports(self) -> list[int]:
        if self.port_range.lower() in ("common", "top"):
            return list(COMMON_PORTS)
        if "-" in self.port_range:
            a, b = self.port_range.split("-", 1)
            start, end = int(a.strip()), int(b.strip())
            return list(range(max(1, start), min(65535, end) + 1))
        return [int(p.strip()) for p in self.port_range.split(",") if p.strip()]

    def _probe(self, port: int) -> dict[str, Any] | None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            if sock.connect_ex((self.target, port)) != 0:
                return None
            banner = ""
            service = socket.getservbyport(port, "tcp") if True else ""
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"
            if self.detect_services:
                try:
                    sock.sendall(b"\r\n")
                    banner = sock.recv(256).decode("utf-8", errors="replace").strip()[:120]
                except OSError:
                    pass
            return {"port": port, "state": "open", "service": service, "banner": banner}
        except OSError:
            return None
        finally:
            sock.close()

    def scan(self) -> dict[str, Any]:
        ports = self._ports()
        open_ports: list[dict[str, Any]] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._probe, p): p for p in ports}
            for fut in concurrent.futures.as_completed(futures):
                result = fut.result()
                if result:
                    open_ports.append(result)

        open_ports.sort(key=lambda x: x["port"])
        return {
            "module": "port_scanner",
            "target": self.target,
            "port_range": self.port_range,
            "scanned": len(ports),
            "open_ports": open_ports,
            "open_count": len(open_ports),
        }
