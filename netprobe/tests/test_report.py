import csv
import io
import json

from netprobe.report import build_report, to_csv, to_html, to_json, to_text
from netprobe.scanner import HostScan, PortResult


def _scan(banner="SSH-2.0-OpenSSH_9.6"):
    return HostScan(
        target="demo.local",
        address="10.0.0.9",
        duration_s=0.42,
        results=[
            PortResult("10.0.0.9", 22, "open", "ssh", banner, 1.5),
            PortResult("10.0.0.9", 23, "closed", "telnet"),
            PortResult("10.0.0.9", 25, "filtered", "smtp"),
        ],
    )


def _report(scan=None, show_all=False):
    return build_report(
        [scan or _scan()], ports_spec="22-25", started_at="2026-10-02T21:00:00+00:00",
        show_all=show_all,
    )


def test_build_report_counts_and_filters_open_only():
    host = _report()["hosts"][0]
    assert host["summary"] == {"open": 1, "closed": 1, "filtered": 1}
    assert [p["port"] for p in host["ports"]] == [22]


def test_build_report_show_all():
    host = _report(show_all=True)["hosts"][0]
    assert [p["port"] for p in host["ports"]] == [22, 23, 25]


def test_json_round_trip():
    data = json.loads(to_json(_report()))
    assert data["tool"] == "netprobe"
    assert data["hosts"][0]["ports"][0]["service"] == "ssh"


def test_text_contains_key_fields():
    text = to_text(_report())
    assert "demo.local (10.0.0.9)" in text
    assert "22/tcp" in text and "SSH-2.0-OpenSSH_9.6" in text
    assert "1 open, 1 closed, 1 filtered" in text


def test_text_reports_resolution_error():
    bad = HostScan("nope.invalid", None, [], 0.0, error="cannot resolve host: x")
    assert "ERROR" in to_text(_report(bad))


def test_csv_structure():
    rows = list(csv.reader(io.StringIO(to_csv(_report()))))
    assert rows[0][:3] == ["target", "address", "port"]
    assert rows[1][2] == "22" and rows[1][3] == "open"


def test_csv_blocks_formula_injection():
    rows = list(csv.reader(io.StringIO(to_csv(_report(_scan("=HYPERLINK(\"http://evil\")"))))))
    banner_cell = rows[1][5]
    assert banner_cell.startswith("'=")


def test_html_escapes_untrusted_banner():
    page = to_html(_report(_scan("<script>alert(1)</script>")))
    assert "<script>" not in page
    assert "&lt;script&gt;" in page
    assert "Content-Security-Policy" in page


def test_html_lists_open_port():
    page = to_html(_report())
    assert "22/tcp" in page and "demo.local" in page
