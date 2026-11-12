# Network Traffic Analysis & Intrusion Detection
A Python-based cybersecurity project for analysing network traffic and detecting suspicious activities.

**[View Live Dashboard](https://networktrafficanalysis-mxc873wjrhqugi9wbthy3w.streamlit.app)**

Technologies Used

* Python
* Streamlit
* Pandas
* Network Traffic Analysis
* Intrusion Detection System

A lightweight, dependency-free Python tool that reads Wireshark captures (`.pcap` and `.pcapng`),
detects common attack patterns, and produces an incident-style report.

Built for learning and lab use. Only analyse traffic you own or are authorised to monitor.

## Quick start (Windows)

1. Install Python 3.8+ from python.org (tick **Add Python to PATH**).
2. Unzip this folder, then double-click `run_demo.bat`.
   It generates a sample capture, analyses it, and runs the tests.
3. Open `sample\sample_report.md`.

Or from Command Prompt / PowerShell in this folder:

```
py make_sample_pcap.py
py analyze.py sample\sample.pcap --out report.md
py -m unittest discover -s tests -v
```

(Use `python` instead of `py` if `py` is not found.) No `pip install` is needed.

## Analysing your own capture

1. In Wireshark, capture on your lab network interface, then **File > Save As** (pcapng or pcap).
2. Run:

```
py analyze.py C:\path\to\capture.pcapng --out incident_report.md --json alerts.json
```

Optional: tune thresholds, e.g. `--set scan_ports=10 --set syn_flood_count=50`.

## What it detects

| Rule | Severity | Logic | MITRE ATT&CK |
|---|---|---|---|
| Port scan | High | 15+ distinct ports hit by SYN-only packets on one host within 10 s | T1046 |
| Host sweep | Medium | One source pings or probes one port on 10+ hosts within 10 s | T1018 |
| SYN flood | High | 100+ SYN-only packets to one host:port within 5 s | T1498 |
| DNS tunnelling | High | 5+ very long or high-entropy DNS queries to one parent domain | T1071.004 |
| ARP spoofing | High | One IP claimed by multiple MAC addresses | T1557.002 |
| Suspicious port | Medium | SYN to ports such as 4444, 31337, 6667 | T1571 |
| Cleartext protocol | Low | Telnet / FTP connection attempts | T1040 |

## Project layout

```
analyze.py            command-line entry point
make_sample_pcap.py   builds a synthetic capture with simulated attacks
run_demo.bat          one-click demo for Windows
nids/pcap_reader.py   pcap and pcapng parsers
nids/decode.py        Ethernet / VLAN / IPv4 / ARP / TCP / UDP / ICMP / DNS decoding
nids/detectors.py     detection rules and thresholds
nids/report.py        console summary, Markdown incident report, JSON export
tests/test_nids.py    unit tests (detections, false positives, pcapng parsing)
docs/                 incident report template and Wireshark filters
```

## Limitations

Threshold-based detection needs tuning per network. IPv4 only (no IPv6), no payload inspection of
encrypted traffic, and the whole capture is loaded into memory, so it suits captures up to a few
hundred MB.

## Ideas to extend

- Add IPv6 support, or HTTP/TLS metadata checks (SNI, user agents).
- Export alerts to a SIEM format (CEF / syslog) or a dashboard.
- Add a brute-force rule for repeated connections to SSH/RDP ports.
