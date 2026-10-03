"""Service-name lookup and banner-based service identification."""

from __future__ import annotations

import re
from typing import Optional

# Well-known TCP ports. This table doubles as the "top" port preset.
SERVICE_NAMES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    5985: "winrm",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}

_BANNER_RULES = (
    (re.compile(r"^SSH-\d"), "ssh"),
    (re.compile(r"^HTTP/\d"), "http"),
    (re.compile(r"^\+OK"), "pop3"),
    (re.compile(r"^\* OK"), "imap"),
)


def service_for_port(port: int) -> str:
    """Return the conventional service name for a port, or ``unknown``."""
    return SERVICE_NAMES.get(port, "unknown")


def identify_banner(banner: Optional[str]) -> Optional[str]:
    """Guess the real service from a banner, independent of the port number.

    Returns ``None`` when the banner is not recognised.
    """
    if not banner:
        return None
    for pattern, name in _BANNER_RULES:
        if pattern.match(banner):
            return name
    if banner.startswith("220"):
        lowered = banner.lower()
        if "ftp" in lowered:
            return "ftp"
        if "smtp" in lowered:
            return "smtp"
    return None
