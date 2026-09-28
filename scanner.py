#!/usr/bin/env python3
"""
Multithreaded TCP Port Scanner + Banner Grabbing + NVD CVE Matching
=====================================================================
Phase of a 4-module security tool:
  1. CLI Interface & Multithreaded TCP Port Scanner   [done]
  2. Banner Grabbing & Service Version Detection       [done]
  3. NVD API Integration & CVE Matching                <-- this file
  4. JSON & HTML Report Generator

LEGAL NOTE: Only scan hosts you own or are explicitly authorized to test
(e.g. scanme.nmap.org, which Nmap's project explicitly permits scanning of,
or 127.0.0.1 / localhost). Unauthorized scanning of third-party systems can
violate computer misuse laws in most jurisdictions.

NVD API NOTE: Get a free API key at https://nvd.nist.gov/developers/request-an-api-key
Without a key: 5 requests / 30s. With a key: 50 requests / 30s. This tool
respects those limits automatically via RateLimiter.
"""

import argparse
import json
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Probe strings for services that stay silent until spoken to.
# ---------------------------------------------------------------------------
PROBE_REQUESTS = {
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\n\r\n",
    443: b"HEAD / HTTP/1.0\r\n\r\n",
}

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class CVEMatch:
    cve_id: str
    description: str
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    published: str = ""


@dataclass
class PortResult:
    port: int
    state: str  # "open", "closed", "filtered/timeout", "error"
    error: str = field(default="")
    service: str = field(default="")
    banner: str = field(default="")
    cve_matches: List[CVEMatch] = field(default_factory=list)
    cve_lookup_note: str = field(default="")  # e.g. "no version detected, skipped"


# ---------------------------------------------------------------------------
# Module 1: scanning (unchanged from Phase 1)
# ---------------------------------------------------------------------------
def scan_port(host: str, port: int, timeout: float) -> PortResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result_code = sock.connect_ex((host, port))
        if result_code == 0:
            return PortResult(port=port, state="open")
        else:
            return PortResult(port=port, state="closed")
    except socket.timeout:
        return PortResult(port=port, state="filtered/timeout")
    except socket.error as e:
        return PortResult(port=port, state="error", error=str(e))
    finally:
        sock.close()


def resolve_target(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        print(f"[!] Could not resolve host '{host}': {e}", file=sys.stderr)
        sys.exit(1)


def parse_port_range(port_arg: str) -> List[int]:
    ports = set()
    for chunk in port_arg.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            start, end = chunk.split("-")
            start, end = int(start), int(end)
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {chunk}")
            ports.update(range(start, end + 1))
        else:
            p = int(chunk)
            if not (1 <= p <= 65535):
                raise ValueError(f"Invalid port: {p}")
            ports.add(p)
    return sorted(ports)


def run_scan(host: str, ports: List[int], timeout: float, max_threads: int) -> List[PortResult]:
    results = []
    total = len(ports)
    completed = 0
    print(f"[*] Scanning {host} — {total} port(s) — {max_threads} threads — {timeout}s timeout\n")
    start = time.time()
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {executor.submit(scan_port, host, port, timeout): port for port in ports}
        try:
            for future in as_completed(future_to_port):
                completed += 1
                results.append(future.result())
                print(f"\r[*] Progress: {completed}/{total}", end="", flush=True)
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user. Cancelling pending tasks...")
            executor.shutdown(wait=False, cancel_futures=True)
            sys.exit(130)
    elapsed = time.time() - start
    print(f"\n[*] Scan completed in {elapsed:.2f}s\n")
    return sorted(results, key=lambda r: r.port)


# ---------------------------------------------------------------------------
# Module 2: banner grabbing (unchanged from Phase 2)
# ---------------------------------------------------------------------------
def guess_service(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def grab_banner(host: str, port: int, timeout: float) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                data = sock.recv(1024)
                if data:
                    return _clean_banner(data)
            except socket.timeout:
                pass
            probe = PROBE_REQUESTS.get(port)
            if probe:
                try:
                    sock.sendall(probe)
                    data = sock.recv(1024)
                    if data:
                        return _clean_banner(data)
                except (socket.timeout, socket.error):
                    pass
            return ""
    except (socket.timeout, socket.error, ConnectionRefusedError):
        return ""


def _clean_banner(raw: bytes) -> str:
    """Decode banner bytes and reduce them to one readable line.

    For HTTP responses the status line alone ("HTTP/1.1 200 OK") says nothing
    about the software, so we also keep the Server header, which is where the
    product and version live (e.g. "Server: Apache/2.4.7 (Ubuntu)")."""
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    first_line = lines[0].strip() if lines else text.strip()

    if first_line.upper().startswith("HTTP/"):
        for line in lines[1:]:
            if line.lower().startswith("server:"):
                return f"{first_line} | {line.strip()}"[:200]

    return first_line[:200]


def run_banner_grab(host: str, results: List[PortResult], timeout: float, max_threads: int) -> None:
    open_results = [r for r in results if r.state == "open"]
    if not open_results:
        return
    print(f"[*] Grabbing banners for {len(open_results)} open port(s)...\n")
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_result = {executor.submit(grab_banner, host, r.port, timeout): r for r in open_results}
        for future in as_completed(future_to_result):
            result_obj = future_to_result[future]
            banner = future.result()
            result_obj.banner = banner
            result_obj.service = _infer_service_from_banner(banner) or guess_service(result_obj.port)


def _infer_service_from_banner(banner: str) -> str:
    if not banner:
        return ""
    lowered = banner.lower()
    if lowered.startswith("ssh-"):
        return "ssh"
    if lowered.startswith("220") and "ftp" in lowered:
        return "ftp"
    if lowered.startswith("220") and ("smtp" in lowered or "mail" in lowered):
        return "smtp"
    if lowered.startswith("http/"):
        return "http"
    return ""


# ---------------------------------------------------------------------------
# Module 3: NVD API integration & CVE matching
# ---------------------------------------------------------------------------

# Each pattern: (compiled regex, product_name). The regex must capture the
# version in group 1. Ordered roughly most-specific-first.
BANNER_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"SSH-\d\.\d-OpenSSH[_-]([\w.]+)", re.IGNORECASE), "openssh"),
    (re.compile(r"Server:\s*nginx/([\w.]+)", re.IGNORECASE), "nginx"),
    (re.compile(r"Server:\s*Apache/([\w.]+)", re.IGNORECASE), "apache http server"),
    (re.compile(r"Server:\s*Microsoft-IIS/([\w.]+)", re.IGNORECASE), "iis"),
    (re.compile(r"\bvsFTPd\s+([\w.]+)", re.IGNORECASE), "vsftpd"),
    (re.compile(r"ProFTPD\s+([\w.]+)", re.IGNORECASE), "proftpd"),
    (re.compile(r"Postfix", re.IGNORECASE), "postfix"),  # no version typically in banner
    (re.compile(r"MySQL[\s-]+([\w.]+)", re.IGNORECASE), "mysql"),
]


def extract_search_term(service: str, banner: str) -> Optional[Tuple[str, Optional[str]]]:
    """
    Attempt to pull a (product, version) pair out of the banner text.
    Returns None if we have nothing usable to search NVD with (e.g. an
    empty banner and an unhelpful generic service name).

    This is intentionally conservative: a wrong/overly-broad keyword search
    against NVD returns noisy, misleading CVE lists, which is worse than
    reporting "insufficient data to match CVEs". So if we can't identify a
    real product from the banner, we do NOT fall back to a generic service
    name like "http" (that would match thousands of unrelated CVEs).
    """
    if banner:
        for pattern, product in BANNER_PATTERNS:
            match = pattern.search(banner)
            if match:
                version = match.group(1) if match.groups() else None
                # OpenSSH banners look like "6.6.1p1" ("p1" = portable release
                # number). NVD indexes these as plain "6.6.1", so strip it.
                if product == "openssh" and version:
                    version = re.sub(r"p\d+$", "", version)
                return (product, version)

    return None


class RateLimiter:
    """
    Sliding-window rate limiter. NVD allows 5 req/30s without a key,
    50 req/30s with one. Rather than a flat sleep(), we track actual
    request timestamps in a deque and only wait as long as truly needed -
    this keeps things fast when under the limit and safe when near it.
    """

    def __init__(self, max_requests: int, window_seconds: float):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._timestamps: deque = deque()

    def wait_if_needed(self) -> None:
        now = time.time()
        # Drop timestamps outside the current window
        while self._timestamps and now - self._timestamps[0] > self.window_seconds:
            self._timestamps.popleft()

        if len(self._timestamps) >= self.max_requests:
            sleep_time = self.window_seconds - (now - self._timestamps[0]) + 0.1
            if sleep_time > 0:
                time.sleep(sleep_time)

        self._timestamps.append(time.time())


class NVDClient:
    """
    Thin wrapper around the NVD CVE API 2.0 keyword search, with:
      - a real sliding-window rate limiter
      - retry-with-backoff on 403/429 (rate limit) responses
      - an in-memory cache so identical (product, version) lookups
        across multiple open ports cost exactly one API call
    """

    def __init__(self, api_key: Optional[str] = None, max_results: int = 5, timeout: float = 10.0):
        self.api_key = api_key
        self.max_results = max_results
        self.timeout = timeout
        # With a key: 50/30s. Without: 5/30s. We shave a little off each
        # for safety margin against clock skew / concurrent tools.
        if api_key:
            self.rate_limiter = RateLimiter(max_requests=45, window_seconds=30)
        else:
            self.rate_limiter = RateLimiter(max_requests=4, window_seconds=30)
        self._cache: Dict[Tuple[str, Optional[str]], List[CVEMatch]] = {}

    def query(self, product: str, version: Optional[str]) -> List[CVEMatch]:
        cache_key = (product.lower(), version)
        if cache_key in self._cache:
            return self._cache[cache_key]

        keyword = f"{product} {version}" if version else product
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": str(self.max_results),
        }
        url = f"{NVD_BASE_URL}?{urllib.parse.urlencode(params)}"

        headers = {"User-Agent": "python-port-scanner-edu-tool/1.0"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        matches = self._request_with_retries(url, headers)
        self._cache[cache_key] = matches
        return matches

    def _request_with_retries(self, url: str, headers: dict, max_retries: int = 3) -> List[CVEMatch]:
        for attempt in range(1, max_retries + 1):
            self.rate_limiter.wait_if_needed()
            req = urllib.request.Request(url, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    body = resp.read()
                    return self._parse_response(body)
            except urllib.error.HTTPError as e:
                if e.code in (403, 429):
                    backoff = 2 ** attempt  # 2s, 4s, 8s
                    print(f"    [!] NVD rate-limited (HTTP {e.code}); backing off {backoff}s "
                          f"(attempt {attempt}/{max_retries})")
                    time.sleep(backoff)
                    continue
                if e.code == 404 and self.api_key:
                    # NVD answers 404 (not 401) when the apiKey header is invalid.
                    print("    [!] NVD returned 404. This usually means the API key is invalid "
                          "or a placeholder. Check it, or run without --nvd-api-key.")
                else:
                    print(f"    [!] NVD HTTP error {e.code} for query: {e.reason}")
                return []
            except urllib.error.URLError as e:
                print(f"    [!] Network error reaching NVD: {e.reason}")
                return []
            except json.JSONDecodeError:
                print("    [!] NVD returned malformed JSON; skipping this lookup")
                return []
        print(f"    [!] Giving up on NVD query after {max_retries} rate-limit retries")
        return []

    @staticmethod
    def _parse_response(body: bytes) -> List[CVEMatch]:
        data = json.loads(body)
        matches = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "UNKNOWN")

            description = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            cvss_score, cvss_severity = NVDClient._extract_cvss(cve)
            published = cve.get("published", "")

            matches.append(CVEMatch(
                cve_id=cve_id,
                description=description[:300],
                cvss_score=cvss_score,
                cvss_severity=cvss_severity,
                published=published,
            ))
        return matches

    @staticmethod
    def _extract_cvss(cve: dict) -> Tuple[Optional[float], Optional[str]]:
        """
        CVSS fallback chain: v3.1 -> v3.0 -> v2. NVD nests these under
        cve['metrics']['cvssMetricV31'][0]['cvssData'], etc.
        """
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key)
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity")
                if score is not None:
                    return float(score), severity
        entries = metrics.get("cvssMetricV2")
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = entries[0].get("baseSeverity")
            if score is not None:
                return float(score), severity
        return None, None


def run_cve_matching(results: List[PortResult], nvd_client: NVDClient) -> None:
    """
    For each open port, extract a search term from its service/banner and
    query NVD. Deliberately sequential (not thread-pooled) because the
    RateLimiter is shared and thread-safety of `deque` append/popleft under
    heavy contention adds complexity we don't need at this request volume -
    NVD's own rate limit caps real-world throughput far below what
    threading would gain us here anyway.
    """
    open_results = [r for r in results if r.state == "open"]
    if not open_results:
        return

    print(f"[*] Querying NVD for CVEs on {len(open_results)} open port(s)...\n")

    for r in open_results:
        term = extract_search_term(r.service, r.banner)
        if term is None:
            r.cve_lookup_note = "insufficient service/version data - skipped"
            continue

        product, version = term
        label = f"{product} {version}" if version else f"{product} (no version - broad search)"
        print(f"    -> Port {r.port}: searching NVD for '{label}'")

        r.cve_matches = nvd_client.query(product, version)
        if not r.cve_matches:
            r.cve_lookup_note = "no CVEs found (or lookup failed)"


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def print_results(host: str, results: List[PortResult], show_closed: bool = False) -> None:
    open_ports = [r for r in results if r.state == "open"]
    other_ports = [r for r in results if r.state != "open"]

    print(f"--- Results for {host} ---")
    if not open_ports:
        print("No open ports found in the given range.")
    else:
        for r in open_ports:
            banner_display = r.banner if r.banner else "(no banner captured)"
            print(f"\nPort {r.port} [{r.state}] — service: {r.service or 'unknown'}")
            print(f"    Banner: {banner_display}")

            if r.cve_matches:
                print(f"    CVEs found ({len(r.cve_matches)}):")
                for cve in r.cve_matches:
                    score_display = f"{cve.cvss_score} ({cve.cvss_severity})" if cve.cvss_score else "no CVSS score"
                    print(f"      - {cve.cve_id}  [{score_display}]")
                    print(f"        {cve.description}")
            elif r.cve_lookup_note:
                print(f"    CVE lookup: {r.cve_lookup_note}")

    if show_closed and other_ports:
        print(f"\n({len(other_ports)} closed/filtered ports omitted; use --show-all to display)")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Multithreaded TCP Port Scanner with banner grabbing and NVD CVE matching.",
        epilog="Example: python3 scanner.py -t scanme.nmap.org -p 22,80 --nvd-api-key YOUR_KEY",
    )
    parser.add_argument("-t", "--target", required=True, help="Target hostname or IP address")
    parser.add_argument("-p", "--ports", default="1-1024",
                         help="Port(s): single (80), range (1-1024), list (22,80,443), or mixed. Default: 1-1024")
    parser.add_argument("--threads", type=int, default=100, help="Concurrent worker threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Per-connection timeout in seconds (default: 1.0)")
    parser.add_argument("--show-all", action="store_true", help="Also display closed/filtered ports")
    parser.add_argument("--no-banner", action="store_true", help="Skip banner grabbing")
    parser.add_argument("--banner-timeout", type=float, default=2.0, help="Timeout for banner grabbing (default: 2.0)")
    parser.add_argument("--no-cve", action="store_true", help="Skip NVD CVE lookups")
    parser.add_argument("--nvd-api-key", type=str, default=None,
                         help="NVD API key (raises rate limit from 5 to 50 req/30s). Get one free at "
                              "https://nvd.nist.gov/developers/request-an-api-key")
    parser.add_argument("--max-cves", type=int, default=5, help="Max CVEs to fetch per service (default: 5)")
    return parser


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    try:
        ports = parse_port_range(args.ports)
    except ValueError as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(1)

    ip = resolve_target(args.target)
    if ip != args.target:
        print(f"[*] Resolved {args.target} -> {ip}")

    results = run_scan(ip, ports, args.timeout, args.threads)

    if not args.no_banner:
        run_banner_grab(ip, results, args.banner_timeout, args.threads)

    if not args.no_cve:
        if not args.nvd_api_key:
            print("[*] No --nvd-api-key supplied - limited to 5 requests/30s. "
                  "Get a free key at https://nvd.nist.gov/developers/request-an-api-key for 50/30s.\n")
        nvd_client = NVDClient(api_key=args.nvd_api_key, max_results=args.max_cves)
        run_cve_matching(results, nvd_client)

    print_results(args.target, results, show_closed=args.show_all)


if __name__ == "__main__":
    main()