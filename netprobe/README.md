# netprobe

[English](README.md) · [Français](README.fr.md)

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

**netprobe** is a small, dependency-free, multithreaded **TCP port scanner** written in pure Python. It detects open ports, grabs service banners, and exports clean reports in text, JSON, CSV or HTML.

I built it as a hands-on way to learn how network scanners work under the hood (TCP handshakes, port states, concurrency, banner fingerprinting) and to practise secure-by-default coding: every piece of data coming from a remote host is treated as untrusted.

> ⚠️ **Legal notice.** Only scan systems you own or have explicit written permission to test. Unauthorised scanning may be illegal in your country. This project is for education and authorised security assessments.

## Features

- **TCP connect scan** with three port states: `open`, `closed` (connection refused) and `filtered` (timeout / network rejection).
- **Multithreaded** (up to 1000 workers) for fast scans of many ports.
- **Banner grabbing** (`-b`) and service identification from the banner itself, not only from the port number (an SSH server on port 2222 is still reported as `ssh`).
- **Flexible targets:** hostnames, IPv4 addresses and CIDR blocks (e.g. `192.168.1.0/28`, capped at 1024 hosts).
- **Flexible ports:** `top` (common service ports), `all`, lists and ranges (`22,80,8000-8100`).
- **Four report formats:** text, JSON, CSV, self-contained HTML. The format is inferred from the output file extension.
- **No root privileges needed** (it uses normal sockets, not raw packets) and **zero third-party dependencies**.

## Installation

```bash
git clone https://github.com/<ayabenakcha002>/netprobe.git
cd netprobe
python -m pip install -e .
```

Requires Python 3.9 or newer. You can also run it without installing: `PYTHONPATH=src python -m netprobe ...`

## Usage

```bash
# Scan the most common ports of a host
netprobe 192.168.1.10

# Specific ports and ranges, with banner grabbing
netprobe 192.168.1.10 -p 22,80,443,8000-8100 -b

# Scan a small subnet and save an HTML report
netprobe 192.168.1.0/28 -p top -b -o report.html

# JSON for further processing, also listing closed/filtered ports
netprobe scanme.example.org -p 1-1024 -a -o scan.json
```

### Options

| Option | Description |
|---|---|
| `TARGET...` | Hostname, IPv4 address or IPv4 CIDR block |
| `-p, --ports` | `top` (default), `all`, or a list/range such as `22,80,8000-8100` |
| `-t, --timeout` | Per-connection timeout in seconds (default `1.0`) |
| `-w, --workers` | Concurrent threads, 1-1000 (default `100`) |
| `-b, --banners` | Grab service banners from open ports |
| `-a, --all` | Include closed and filtered ports in the report |
| `-o, --output FILE` | Write the report to a file (format from extension) |
| `-f, --format` | Force `text`, `json`, `csv` or `html` |
| `-q, --quiet` | No live progress or legal notice on stderr |

Exit codes: `0` success, `1` no target could be resolved, `2` invalid arguments.

### Example (real output against local test servers)

```text
$ netprobe 127.0.0.1 -p 2222,8080,9999 -b
netprobe: only scan systems you own or have explicit written permission to test.
[*] Scanning 127.0.0.1 (3 ports)...
[+] 127.0.0.1:2222/tcp open ssh
[+] 127.0.0.1:8080/tcp open http
netprobe 0.1.0 - scan started 2026-10-02T21:11:46+00:00

Target: 127.0.0.1 (127.0.0.1) - 2 open, 1 closed, 0 filtered - 0.006s
  PORT     STATE     SERVICE        BANNER
  2222/tcp open      ssh            SSH-2.0-OpenSSH_9.6p1 Ubuntu
  8080/tcp open      http           HTTP/1.0 200 OK | Server: SimpleHTTP/0.6 Python/3.13.16
```

Live progress goes to **stderr** and the report to **stdout**, so you can pipe or redirect the report cleanly.

<details>
<summary>JSON report excerpt</summary>

```json
{
  "tool": "netprobe",
  "version": "0.1.0",
  "started_at": "2026-10-02T21:11:46+00:00",
  "ports_spec": "2222,8080,9999",
  "hosts": [
    {
      "target": "127.0.0.1",
      "address": "127.0.0.1",
      "summary": { "open": 2, "closed": 1, "filtered": 0 },
      "ports": [
        {
          "port": 2222,
          "state": "open",
          "service": "ssh",
          "banner": "SSH-2.0-OpenSSH_9.6p1 Ubuntu",
          "latency_ms": 2.71
        }
      ]
    }
  ]
}
```
</details>

## How it works

1. **Parse** the targets and port specification (`ports.py`), validating ranges and capping CIDR expansion.
2. **Resolve** the target, then submit one probe per port to a thread pool (`scanner.py`). Scanning is I/O-bound, so threads give a near-linear speed-up despite the GIL.
3. **Classify** each port from the outcome of `connect()`:
   - handshake completes → `open`
   - connection refused (RST) → `closed`
   - timeout or other network error → `filtered`
4. **Fingerprint** (optional): read the greeting banner (HTTP ports get a `HEAD /` request first) and map it to a service (`services.py`).
5. **Report** the results in the requested format (`report.py`).

```text
src/netprobe/
├── cli.py       argument parsing, live output, exit codes
├── ports.py     port/target parsing and validation
├── scanner.py   threaded connect scan, banner grabbing
├── services.py  port → service table, banner fingerprinting
└── report.py    text / JSON / CSV / HTML renderers
tests/           70 unit tests (local sockets, no internet needed)
```

## Security considerations

A scanner reads data from machines it does not control, so the output side matters as much as the scanning side:

- **Terminal injection:** banners are stripped of control characters (including ANSI escape sequences) and truncated.
- **HTML injection / XSS:** all values are HTML-escaped and the generated page ships with a restrictive Content-Security-Policy.
- **CSV formula injection:** cells starting with `=`, `+`, `-` or `@` are prefixed with `'` so spreadsheet software does not execute them.
- **Resource limits:** CIDR expansion is capped, workers are bounded and timeouts must be positive.

All of these behaviours are covered by tests.

## Tests

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

The tests spin up throw-away servers on `127.0.0.1`, so they run offline. GitHub Actions runs them on Python 3.9 to 3.13 (see `.github/workflows/ci.yml`).

## Limitations and roadmap

- IPv4 only, TCP connect scan only (no SYN/stealth scan, no UDP).
- Banner grabbing does not negotiate TLS, so HTTPS ports return no banner yet.
- Planned: IPv6, TLS certificate inspection, UDP probes for common services, rate limiting, and comparing two scan reports to detect changes.

## License

MIT. See [LICENSE](LICENSE).
