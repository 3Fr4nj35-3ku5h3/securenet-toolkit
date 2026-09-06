#!/usr/bin/env python3
"""
SecureNet Toolkit — Network security automation suite
Author: Francis Ngumi Kuria
Version: 1.1.0
License: MIT

Authorized testing only.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Optional

from modules import port_scanner, network_mapper, dns_enum, ssl_analyzer, http_analyzer
from utils import logger, reporter

__version__ = "1.1.0"

BANNER = f"""
╔══════════════════════════════════════════════════════════════╗
║              SecureNet Toolkit v{__version__}                         ║
║        Network Security Automation Suite                     ║
║        Authorized testing environments only                  ║
╚══════════════════════════════════════════════════════════════╝
"""


class SecureNetToolkit:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.logger = logger.setup_logger(verbose)

    def run_port_scan(self, target: str, port_range: str = "1-1000", detect_services: bool = False) -> dict[str, Any]:
        self.logger.info(f"Port scan → {target} ({port_range})")
        results = port_scanner.PortScanner(target, port_range, detect_services).scan()
        self.logger.info(f"Open ports: {results.get('open_count', 0)}")
        return results

    def run_network_discovery(self, network: str) -> dict[str, Any]:
        self.logger.info(f"Host discovery → {network}")
        results = network_mapper.NetworkMapper(network).discover_hosts()
        self.logger.info(f"Hosts found: {results.get('host_count', 0)}")
        return results

    def run_dns_enum(self, domain: str, wordlist: Optional[str] = None) -> dict[str, Any]:
        self.logger.info(f"DNS enum → {domain}")
        results = dns_enum.DNSEnumerator(domain, wordlist).enumerate()
        self.logger.info(f"Subdomains: {results.get('subdomain_count', 0)}")
        return results

    def run_ssl_check(self, target: str, check_expiry: bool = True) -> dict[str, Any]:
        self.logger.info(f"SSL/TLS → {target}")
        results = ssl_analyzer.SSLAnalyzer(target, check_expiry).analyze()
        self.logger.info(f"Grade: {results.get('grade', 'N/A')}")
        return results

    def run_http_headers_check(self, url: str) -> dict[str, Any]:
        self.logger.info(f"HTTP headers → {url}")
        results = http_analyzer.HTTPAnalyzer(url).analyze_headers()
        self.logger.info(f"Score: {results.get('score', 0)}/100")
        return results


def _print_results(results: dict[str, Any]) -> None:
    print(json.dumps(results, indent=2, default=str))


def interactive_mode() -> None:
    print(BANNER)
    toolkit = SecureNetToolkit(verbose=True)

    menu = """
[1] Port Scanner
[2] Network Discovery
[3] DNS Enumeration
[4] SSL/TLS Analyzer
[5] HTTP Security Headers
[0] Exit
"""
    while True:
        print(menu)
        choice = input("Select: ").strip()
        try:
            if choice == "1":
                target = input("Target IP/hostname: ").strip()
                port_range = input("Port range [1-1000|common]: ").strip() or "common"
                detect = input("Banner grab? (y/N): ").strip().lower() == "y"
                _print_results(toolkit.run_port_scan(target, port_range, detect))
            elif choice == "2":
                network = input("Network (e.g. 192.168.1.0/24): ").strip()
                _print_results(toolkit.run_network_discovery(network))
            elif choice == "3":
                domain = input("Domain: ").strip()
                wordlist = input("Wordlist path (optional): ").strip() or None
                _print_results(toolkit.run_dns_enum(domain, wordlist))
            elif choice == "4":
                target = input("Host: ").strip()
                _print_results(toolkit.run_ssl_check(target))
            elif choice == "5":
                url = input("URL: ").strip()
                _print_results(toolkit.run_http_headers_check(url))
            elif choice == "0":
                print("Stay secure.")
                return
            else:
                print("Invalid option.")
        except KeyboardInterrupt:
            print("\nInterrupted.")
            return
        except Exception as e:
            print(f"[!] {e}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SecureNet Toolkit — authorized network security checks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
        "  python securenet.py --scan-ports scanme.nmap.org --port-range common\n"
        "  python securenet.py --ssl-check example.com --report json\n"
        "  python securenet.py --http-headers https://example.com\n",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true")

    parser.add_argument("--scan-ports", metavar="TARGET")
    parser.add_argument("--port-range", default="common", help="1-1000, common, or comma list")
    parser.add_argument("--detect-services", action="store_true")

    parser.add_argument("--discover-hosts", metavar="NETWORK")
    parser.add_argument("--dns-enum", metavar="DOMAIN")
    parser.add_argument("--wordlist", metavar="FILE")

    parser.add_argument("--ssl-check", metavar="TARGET")
    parser.add_argument("--cert-expiry", action="store_true", default=True)

    parser.add_argument("--http-headers", metavar="URL")
    parser.add_argument("--report", choices=["json", "csv", "html"])

    args = parser.parse_args()

    if len(sys.argv) == 1:
        interactive_mode()
        return

    toolkit = SecureNetToolkit(verbose=args.verbose)
    results: dict[str, Any] = {}

    if args.scan_ports:
        results = toolkit.run_port_scan(args.scan_ports, args.port_range, args.detect_services)
    elif args.discover_hosts:
        results = toolkit.run_network_discovery(args.discover_hosts)
    elif args.dns_enum:
        results = toolkit.run_dns_enum(args.dns_enum, args.wordlist)
    elif args.ssl_check:
        results = toolkit.run_ssl_check(args.ssl_check, args.cert_expiry)
    elif args.http_headers:
        results = toolkit.run_http_headers_check(args.http_headers)
    else:
        parser.print_help()
        return

    _print_results(results)

    if results and args.report:
        path = reporter.ReportGenerator(results, args.report).generate()
        print(f"\n[+] Report saved: {path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(0)
