import socket

import pytest

from netprobe import scanner
from netprobe.scanner import (
    probe_port,
    sanitize_banner,
    scan_host,
    summarize_http_response,
)
from netprobe.services import identify_banner, service_for_port


def test_open_port(banner_server):
    port = banner_server()
    result = probe_port("127.0.0.1", port, timeout=1.0)
    assert result.state == "open"
    assert result.latency_ms is not None
    assert result.banner is None  # banner grabbing is opt-in


def test_closed_port(closed_port):
    result = probe_port("127.0.0.1", closed_port, timeout=1.0)
    assert result.state == "closed"
    assert result.latency_ms is None


def test_timeout_is_reported_as_filtered(monkeypatch):
    def fake_connect(*args, **kwargs):
        raise socket.timeout("timed out")

    monkeypatch.setattr(scanner.socket, "create_connection", fake_connect)
    assert probe_port("203.0.113.1", 80, timeout=0.1).state == "filtered"


def test_network_error_is_reported_as_filtered(monkeypatch):
    def fake_connect(*args, **kwargs):
        raise OSError("network unreachable")

    monkeypatch.setattr(scanner.socket, "create_connection", fake_connect)
    assert probe_port("203.0.113.1", 80, timeout=0.1).state == "filtered"


def test_banner_grab_identifies_service_regardless_of_port(banner_server):
    port = banner_server(b"SSH-2.0-OpenSSH_9.6\r\n")
    result = probe_port("127.0.0.1", port, timeout=1.0, grab_banner=True)
    assert result.banner == "SSH-2.0-OpenSSH_9.6"
    assert result.service == "ssh"


def test_banner_control_characters_are_neutralised(banner_server):
    port = banner_server(b"SSH-2.0-x\x1b[31mRED\x07\r\n")
    result = probe_port("127.0.0.1", port, timeout=1.0, grab_banner=True)
    assert "\x1b" not in result.banner
    assert "\x07" not in result.banner


def test_silent_server_gives_no_banner(banner_server):
    port = banner_server(b"")
    result = probe_port("127.0.0.1", port, timeout=0.3, grab_banner=True)
    assert result.state == "open"
    assert result.banner is None


def test_sanitize_banner_truncates_and_keeps_first_line():
    raw = b"A" * 500 + b"\nsecond line"
    cleaned = sanitize_banner(raw)
    assert len(cleaned) == scanner.MAX_BANNER_LENGTH
    assert sanitize_banner(b"   \r\n") is None
    assert sanitize_banner(b"hello\nworld") == "hello"


def test_summarize_http_response():
    raw = b"HTTP/1.0 200 OK\r\nDate: x\r\nServer: nginx/1.25\r\n\r\n"
    assert summarize_http_response(raw) == "HTTP/1.0 200 OK | Server: nginx/1.25"
    assert summarize_http_response(b"HTTP/1.1 404 Not Found\r\n\r\n") == "HTTP/1.1 404 Not Found"
    assert summarize_http_response(b"") is None


def test_scan_host_mixed_results_sorted(banner_server, closed_port):
    open_port = banner_server(b"220 mail ESMTP ready\r\n")
    seen = []
    scan = scan_host(
        "127.0.0.1",
        [open_port, closed_port],
        timeout=1.0,
        workers=4,
        grab_banners=True,
        on_result=seen.append,
    )
    assert scan.error is None
    assert scan.address == "127.0.0.1"
    assert [r.port for r in scan.results] == sorted([open_port, closed_port])
    assert [r.port for r in scan.open_ports] == [open_port]
    assert scan.open_ports[0].service == "smtp"
    assert len(seen) == 2  # callback fired once per probe


def test_scan_host_unresolvable_target():
    scan = scan_host("host-that-does-not-exist.invalid", [80], timeout=0.5)
    assert scan.address is None
    assert scan.results == []
    assert "cannot resolve" in scan.error


def test_scan_host_with_no_ports_does_not_crash():
    scan = scan_host("127.0.0.1", [], timeout=0.5)
    assert scan.results == []


@pytest.mark.parametrize(
    "banner,expected",
    [
        ("SSH-2.0-OpenSSH_9.6", "ssh"),
        ("HTTP/1.1 200 OK", "http"),
        ("+OK Dovecot ready", "pop3"),
        ("* OK IMAP4rev1", "imap"),
        ("220 ProFTPD Server", "ftp"),
        ("220 mail.example.com ESMTP Postfix", "smtp"),
        ("220 something else", None),
        ("random noise", None),
        ("", None),
        (None, None),
    ],
)
def test_identify_banner(banner, expected):
    assert identify_banner(banner) == expected


def test_service_for_port():
    assert service_for_port(22) == "ssh"
    assert service_for_port(54321) == "unknown"
