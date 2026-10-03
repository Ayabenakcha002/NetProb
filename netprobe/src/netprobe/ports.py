"""Parsing of port specifications and scan targets."""

from __future__ import annotations

import ipaddress
from typing import List

from .services import SERVICE_NAMES

TOP_PORTS = tuple(sorted(SERVICE_NAMES))

# Safety valve: refuse to expand a CIDR block into an unreasonable host list.
MAX_HOSTS = 1024


def _to_port(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise ValueError(f"invalid port: {text!r}") from None
    if not 1 <= value <= 65535:
        raise ValueError(f"port out of range (1-65535): {value}")
    return value


def parse_ports(spec: str) -> List[int]:
    """Turn a spec such as ``22,80,8000-8100`` into a sorted, unique list.

    Special tokens: ``top`` (common service ports) and ``all`` (1-65535).
    """
    if not spec or not spec.strip():
        raise ValueError("empty port specification")

    ports = set()
    for part in spec.lower().split(","):
        part = part.strip()
        if not part:
            continue
        if part == "top":
            ports.update(TOP_PORTS)
        elif part == "all":
            ports.update(range(1, 65536))
        elif "-" in part:
            low_text, high_text = part.split("-", 1)
            low, high = _to_port(low_text), _to_port(high_text)
            if low > high:
                raise ValueError(f"invalid range (start > end): {part!r}")
            ports.update(range(low, high + 1))
        else:
            ports.add(_to_port(part))

    if not ports:
        raise ValueError("empty port specification")
    return sorted(ports)


def expand_targets(target: str) -> List[str]:
    """Expand a CIDR block into host addresses; pass anything else through."""
    target = target.strip()
    if not target:
        raise ValueError("empty target")
    if "/" not in target:
        return [target]

    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        raise ValueError(f"invalid CIDR block: {target!r}") from None
    if network.version != 4:
        raise ValueError("only IPv4 targets are supported")
    if network.num_addresses > MAX_HOSTS + 2:
        raise ValueError(
            f"{target} expands to more than {MAX_HOSTS} hosts; use a smaller block"
        )
    if network.num_addresses == 1:
        return [str(network.network_address)]
    return [str(host) for host in network.hosts()]
