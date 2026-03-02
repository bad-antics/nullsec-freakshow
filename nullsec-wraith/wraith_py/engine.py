"""
👻 wraith engine (Python) — Ephemeral Port Scanner
Concurrent socket-based scanner with ephemeral port detection.
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field


COMMON_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 111: "rpc", 135: "msrpc",
    139: "netbios", 143: "imap", 443: "https", 445: "smb", 465: "smtps",
    587: "submission", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
    8888: "http-alt2", 9090: "prometheus", 9200: "elasticsearch",
    27017: "mongodb", 6443: "k8s-api",
}

SUSPICIOUS_PORTS = {
    4444: "metasploit", 5555: "android-adb", 1337: "waste",
    31337: "eleet", 12345: "netbus", 27374: "subseven",
    6667: "irc-backdoor", 6697: "irc-ssl", 9999: "abyss",
    4443: "pharos", 8081: "sunproxy", 1234: "hotline",
}


@dataclass
class ScanResult:
    host: str
    port: int
    open: bool
    service: str = ""
    suspicious: bool = False
    latency_ms: float = 0.0


def scan_port(host: str, port: int, timeout: float = 1.0) -> ScanResult:
    """Scan a single port."""
    start = time.monotonic()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            elapsed = (time.monotonic() - start) * 1000
            if result == 0:
                service = COMMON_SERVICES.get(port, "")
                suspicious = port in SUSPICIOUS_PORTS
                if suspicious and not service:
                    service = SUSPICIOUS_PORTS[port]
                return ScanResult(host, port, True, service, suspicious, elapsed)
    except (socket.timeout, OSError):
        pass
    return ScanResult(host, port, False)


def ghost_scan(host: str, start_port: int, end_port: int,
               workers: int = 100, timeout: float = 1.0) -> list[ScanResult]:
    """Concurrent port scan."""
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(scan_port, host, port, timeout): port
            for port in range(start_port, end_port + 1)
        }
        for future in as_completed(futures):
            result = future.result()
            if result.open:
                results.append(result)
    results.sort(key=lambda r: r.port)
    return results


def haunt_scan(host: str, start_port: int = 1, end_port: int = 65535,
               rounds: int = 3, workers: int = 100, timeout: float = 1.0) -> dict:
    """Multi-round scan to detect ephemeral/transient ports."""
    round_results = []
    for i in range(rounds):
        results = ghost_scan(host, start_port, end_port, workers, timeout)
        open_ports = {r.port for r in results}
        round_results.append(open_ports)

    if not round_results:
        return {"stable": [], "ephemeral": [], "rounds": rounds}

    # Stable = open in all rounds, ephemeral = open in some but not all
    all_seen = set()
    for rr in round_results:
        all_seen |= rr

    stable = []
    ephemeral = []
    for port in sorted(all_seen):
        count = sum(1 for rr in round_results if port in rr)
        service = COMMON_SERVICES.get(port, SUSPICIOUS_PORTS.get(port, ""))
        if count == rounds:
            stable.append({"port": port, "service": service, "rounds": count})
        else:
            ephemeral.append({"port": port, "service": service, "rounds": count})

    return {"stable": stable, "ephemeral": ephemeral, "rounds": rounds}
