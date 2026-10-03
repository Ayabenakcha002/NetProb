import json

import pytest

from netprobe import __version__
from netprobe.cli import main


def test_scan_open_port_text_output(banner_server, capsys):
    port = banner_server(b"SSH-2.0-TestServer\r\n")
    code = main(["127.0.0.1", "-p", str(port), "-b", "-q", "-t", "1"])
    out = capsys.readouterr().out
    assert code == 0
    assert f"{port}/tcp" in out and "SSH-2.0-TestServer" in out


def test_json_file_output_inferred_from_extension(banner_server, tmp_path, capsys):
    port = banner_server()
    target = tmp_path / "report.json"
    code = main(["127.0.0.1", "-p", str(port), "-q", "-o", str(target)])
    assert code == 0
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["hosts"][0]["ports"][0]["port"] == port
    assert capsys.readouterr().out == ""  # nothing on stdout when writing a file


def test_html_and_csv_outputs(banner_server, tmp_path):
    port = banner_server()
    html_file, csv_file = tmp_path / "r.html", tmp_path / "r.csv"
    main(["127.0.0.1", "-p", str(port), "-q", "-o", str(html_file)])
    main(["127.0.0.1", "-p", str(port), "-q", "-o", str(csv_file)])
    assert "<table>" in html_file.read_text(encoding="utf-8")
    assert csv_file.read_text(encoding="utf-8").startswith("target,address,port")


def test_explicit_format_overrides_extension(banner_server, tmp_path):
    port = banner_server()
    target = tmp_path / "report.txt"
    main(["127.0.0.1", "-p", str(port), "-q", "-f", "json", "-o", str(target)])
    assert json.loads(target.read_text(encoding="utf-8"))["tool"] == "netprobe"


def test_show_all_lists_closed_ports(closed_port, capsys):
    main(["127.0.0.1", "-p", str(closed_port), "-q", "-a"])
    assert "closed" in capsys.readouterr().out


def test_live_progress_goes_to_stderr(banner_server, capsys):
    port = banner_server()
    main(["127.0.0.1", "-p", str(port)])
    err = capsys.readouterr().err
    assert "only scan systems you own" in err
    assert f"127.0.0.1:{port}/tcp open" in err


def test_unresolvable_target_returns_exit_code_1(capsys):
    assert main(["host-that-does-not-exist.invalid", "-p", "80", "-q", "-t", "0.5"]) == 1


@pytest.mark.parametrize(
    "argv",
    [
        ["127.0.0.1", "-p", "99999"],
        ["127.0.0.1", "-p", "abc"],
        ["10.0.0.0/8"],
        ["127.0.0.1", "-t", "0"],
        ["127.0.0.1", "-w", "0"],
        ["127.0.0.1", "-w", "5000"],
        [],
    ],
)
def test_invalid_arguments_exit_with_code_2(argv):
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out
