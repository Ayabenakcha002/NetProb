"""Command-line interface for netprobe."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from . import __version__
from .ports import expand_targets, parse_ports
from .report import RENDERERS, build_report
from .scanner import PortResult, scan_host

NOTICE = (
    "netprobe: only scan systems you own or have explicit written "
    "permission to test."
)
_EXTENSION_FORMATS = {"txt": "text", "json": "json", "csv": "csv", "html": "html", "htm": "html"}


def _positive_float(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid number: {text!r}") from None
    if value <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return value


def _worker_count(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid integer: {text!r}") from None
    if not 1 <= value <= 1000:
        raise argparse.ArgumentTypeError("must be between 1 and 1000")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netprobe",
        description="Multithreaded TCP port scanner with banner grabbing and "
        "JSON/CSV/HTML reports.",
        epilog=NOTICE,
    )
    parser.add_argument(
        "targets",
        nargs="+",
        metavar="TARGET",
        help="hostname, IPv4 address or IPv4 CIDR block (e.g. 192.168.1.0/28)",
    )
    parser.add_argument(
        "-p", "--ports", default="top",
        help="ports to scan: 'top' (default), 'all', or a list such as 22,80,8000-8100",
    )
    parser.add_argument("-t", "--timeout", type=_positive_float, default=1.0,
                        help="per-connection timeout in seconds (default: 1.0)")
    parser.add_argument("-w", "--workers", type=_worker_count, default=100,
                        help="number of concurrent threads, 1-1000 (default: 100)")
    parser.add_argument("-b", "--banners", action="store_true",
                        help="grab service banners from open ports")
    parser.add_argument("-a", "--all", action="store_true", dest="show_all",
                        help="also list closed and filtered ports in the report")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="write the report to FILE (format inferred from extension)")
    parser.add_argument("-f", "--format", choices=sorted(RENDERERS),
                        help="report format (default: from --output extension, else text)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="no live progress or legal notice on stderr")
    parser.add_argument("--version", action="version", version=f"netprobe {__version__}")
    return parser


def _choose_format(output: Optional[str], explicit: Optional[str]) -> str:
    if explicit:
        return explicit
    if output:
        suffix = Path(output).suffix.lower().lstrip(".")
        if suffix in _EXTENSION_FORMATS:
            return _EXTENSION_FORMATS[suffix]
    return "text"


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        ports = parse_ports(args.ports)
        targets: List[str] = []
        for entry in args.targets:
            for host in expand_targets(entry):
                if host not in targets:
                    targets.append(host)
    except ValueError as exc:
        parser.error(str(exc))

    if not args.quiet:
        print(NOTICE, file=sys.stderr)

    def live(result: PortResult) -> None:
        if result.state == "open":
            print(f"[+] {result.host}:{result.port}/tcp open {result.service}", file=sys.stderr)

    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    scans = []
    for target in targets:
        if not args.quiet:
            print(f"[*] Scanning {target} ({len(ports)} ports)...", file=sys.stderr)
        scans.append(
            scan_host(
                target,
                ports,
                timeout=args.timeout,
                workers=args.workers,
                grab_banners=args.banners,
                on_result=None if args.quiet else live,
            )
        )

    report = build_report(
        scans, ports_spec=args.ports, started_at=started_at, show_all=args.show_all
    )
    rendered = RENDERERS[_choose_format(args.output, args.format)](report)

    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
        if not args.quiet:
            print(f"[*] Report written to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(rendered)

    return 1 if all(scan.error for scan in scans) else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
