"""Host discovery via TCP connect sweep on common ports (no raw ICMP required)."""

from __future__ import annotations

import concurrent.futures
import ipaddress
import socket
from typing import Any


PROBE_PORTS = (80, 443, 22, 445, 3389)


class NetworkMapper:
    def __init__(self, network: str, timeout: float = 0.5, max_workers: int = 100):
        self.network = network
        self.timeout = timeout
        self.max_workers = max_workers

    def _alive(self, ip: str) -> str | None:
        for port in PROBE_PORTS:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            try:
                if sock.connect_ex((ip, port)) == 0:
                    return ip
            except OSError:
                pass
            finally:
                sock.close()
        return None

    def discover_hosts(self) -> dict[str, Any]:
        try:
            net = ipaddress.ip_network(self.network, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid network: {self.network}") from e

        hosts = [str(h) for h in net.hosts()]
        # Cap large ranges for safety
        if len(hosts) > 1024:
            hosts = hosts[:1024]

        found: list[str] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            for result in pool.map(self._alive, hosts):
                if result:
                    found.append(result)

        found.sort(key=lambda x: ipaddress.ip_address(x))
        return {
            "module": "network_mapper",
            "network": self.network,
            "probed": len(hosts),
            "hosts": found,
            "host_count": len(found),
            "note": "TCP connect probe on ports 80/443/22/445/3389 (no root required)",
        }
