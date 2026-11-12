"""Command-line entry point.

    python analyze.py capture.pcapng --out report.md
    python analyze.py capture.pcap --json alerts.json --set scan_ports=10
"""
import argparse
import sys

from nids.decode import decode
from nids.detectors import DEFAULTS, run_all
from nids.pcap_reader import read_packets
from nids.report import compute_stats, console_summary, write_json, write_markdown


def main(argv=None):
    ap = argparse.ArgumentParser(description="Analyse a Wireshark capture and flag suspicious traffic.")
    ap.add_argument("pcap", help="path to a .pcap or .pcapng file")
    ap.add_argument("--out", default="incident_report.md", help="Markdown report path")
    ap.add_argument("--json", help="also write alerts as JSON")
    ap.add_argument("--set", action="append", default=[], metavar="KEY=VALUE",
                    help="override a threshold, e.g. --set scan_ports=10 (keys: %s)" % ", ".join(DEFAULTS))
    args = ap.parse_args(argv)

    overrides = {}
    for item in args.set:
        key, _, val = item.partition("=")
        if key not in DEFAULTS:
            ap.error("unknown threshold %r" % key)
        overrides[key] = type(DEFAULTS[key])(val)

    try:
        pkts = [p for p in (decode(*r) for r in read_packets(args.pcap)) if p]
    except (OSError, ValueError) as e:
        print("Error: %s" % e, file=sys.stderr)
        return 1
    pkts.sort(key=lambda p: p["ts"])
    if not pkts:
        print("No IPv4/ARP packets found in capture.", file=sys.stderr)
        return 1

    stats = compute_stats(pkts)
    alerts = run_all(pkts, overrides)
    print(console_summary(args.pcap, stats, alerts))
    write_markdown(args.out, args.pcap, stats, alerts)
    print("\nIncident report written to %s" % args.out)
    if args.json:
        write_json(args.json, args.pcap, stats, alerts)
        print("JSON written to %s" % args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
