"""Core scanning logic: TCP connect scan with optional banner grabbing."""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Callable, Iterable, List, Optional

from .services import identify_banner, service_for_port

# Ports on which we speak first (HTTP) to coax a banner out of the server.
HTTP_PORTS = frozenset({80, 8000, 8080, 8888})

MAX_BANNER_LENGTH = 120


@dataclass
class PortResult:
    host: str
    port: int
    state: str  # "open" | "closed" | "filtered"
    service: str
    banner: Optional[str] = None
    latency_ms: Optional[float] = None


@dataclass
class HostScan:
    target: str
    address: Optional[str]
    results: List[PortResult] = field(default_factory=list)
    duration_s: float = 0.0
    error: Optional[str] = None

    @property
    def open_ports(self) -> List[PortResult]:
        return [r for r in self.results if r.state == "open"]

    def to_dict(self) -> dict:
        data = asdict(self)
        return data


def sanitize_banner(raw: bytes) -> Optional[str]:
    """Decode a banner and neutralise control characters.

    Banners come from the remote host and are therefore untrusted: a hostile
    server could embed terminal escape sequences to tamper with our output.
    """
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        return None
    first_line = text.splitlines()[0]
    cleaned = "".join(ch if ch.isprintable() else "?" for ch in first_line)
    return cleaned[:MAX_BANNER_LENGTH] or None


def summarize_http_response(raw: bytes) -> Optional[str]:
    """Reduce an HTTP response head to ``status line | Server: value``."""
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if not lines:
        return None
    summary = lines[0].strip()
    for line in lines[1:]:
        if line.lower().startswith("server:"):
            summary += " | " + line.strip()
            break
    return sanitize_banner(summary.encode("utf-8"))


def _grab_banner(sock: socket.socket, host: str, port: int, timeout: float) -> Optional[str]:
    try:
        sock.settimeout(timeout)
        if port in HTTP_PORTS:
            request = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n"
            sock.sendall(request.encode("ascii", errors="ignore"))
            return summarize_http_response(sock.recv(1024))
        return sanitize_banner(sock.recv(256))
    except OSError:
        return None


def probe_port(host: str, port: int, timeout: float = 1.0, grab_banner: bool = False) -> PortResult:
    """Attempt one TCP connection and classify the port.

    * ``open``     - the handshake completed
    * ``closed``   - the host actively refused the connection (RST)
    * ``filtered`` - no answer (timeout) or the network rejected the attempt
    """
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            latency = round((time.perf_counter() - started) * 1000, 2)
            banner = _grab_banner(sock, host, port, timeout) if grab_banner else None
        service = identify_banner(banner) or service_for_port(port)
        return PortResult(host, port, "open", service, banner, latency)
    except ConnectionRefusedError:
        return PortResult(host, port, "closed", service_for_port(port))
    except (socket.timeout, OSError):
        return PortResult(host, port, "filtered", service_for_port(port))


def scan_host(
    target: str,
    ports: Iterable[int],
    *,
    timeout: float = 1.0,
    workers: int = 100,
    grab_banners: bool = False,
    on_result: Optional[Callable[[PortResult], None]] = None,
) -> HostScan:
    """Scan ``ports`` on one target using a thread pool.

    Connection attempts are I/O-bound, so threads give near-linear speed-ups
    despite the GIL. ``on_result`` is invoked for every finished probe, which
    lets the CLI stream open ports as they are found.
    """
    started = time.perf_counter()
    try:
        address = socket.gethostbyname(target)
    except OSError as exc:
        return HostScan(target, None, [], 0.0, error=f"cannot resolve host: {exc}")

    port_list = list(ports)
    results: List[PortResult] = []
    pool_size = max(1, min(workers, len(port_list)))
    with ThreadPoolExecutor(max_workers=pool_size) as pool:
        futures = [
            pool.submit(probe_port, address, port, timeout, grab_banners)
            for port in port_list
        ]
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            if on_result is not None:
                on_result(result)

    results.sort(key=lambda r: r.port)
    return HostScan(
        target=target,
        address=address,
        results=results,
        duration_s=round(time.perf_counter() - started, 3),
    )
