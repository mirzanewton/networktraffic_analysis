"""Console summary, incident-style Markdown report and JSON export."""
import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone

ADVICE = {
    "Port scan": "Block or rate-limit the source at the firewall; check the target for exposed services.",
    "Host sweep": "Investigate the source host for compromise; restrict ICMP and lateral traffic between segments.",
    "SYN flood": "Enable SYN cookies and rate limiting; engage the upstream provider if the flood continues.",
    "DNS tunnelling / exfiltration": "Block the domain, inspect the source host for malware, and review data leaving via DNS.",
    "ARP spoofing": "Enable dynamic ARP inspection / port security; locate the rogue MAC on the switch.",
    "Suspicious port": "Identify the process behind the connection and check for backdoors or C2 beacons.",
    "Cleartext protocol": "Replace with SSH / SFTP / FTPS and disable the legacy service.",
}


def fmt_ts(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def compute_stats(pkts):
    stats = {
        "packets": len(pkts),
        "bytes": sum(p["len"] for p in pkts),
        "first": min(p["ts"] for p in pkts) if pkts else 0,
        "last": max(p["ts"] for p in pkts) if pkts else 0,
        "protocols": Counter(p["proto"] for p in pkts),
        "talkers": Counter(),
    }
    for p in pkts:
        if "src" in p:
            stats["talkers"][p["src"]] += p["len"]
    return stats


def console_summary(name, stats, alerts):
    out = ["", "File: %s" % name,
           "Packets: %d  Bytes: %d  Span: %.1fs" % (stats["packets"], stats["bytes"],
                                                     stats["last"] - stats["first"]),
           "Protocols: " + ", ".join("%s=%d" % kv for kv in stats["protocols"].most_common()),
           "", "ALERTS (%d)" % len(alerts), "-" * 78]
    for a in alerts:
        out.append("[%-6s] %-30s %s -> %s" % (a.severity, a.rule, a.src, a.dst))
        out.append("         %s" % a.detail)
    if not alerts:
        out.append("No alerts raised.")
    return "\n".join(out)


def write_markdown(path, name, stats, alerts):
    sev = Counter(a.severity for a in alerts)
    L = ["# Network Security Incident Report", "",
         "**Capture analysed:** `%s`  " % name,
         "**Capture window:** %s to %s  " % (fmt_ts(stats["first"]), fmt_ts(stats["last"])),
         "**Report generated:** %s  " % fmt_ts(datetime.now(timezone.utc).timestamp()),
         "**Tool:** nids (pure-Python traffic analysis and intrusion detection)", "",
         "## 1. Executive summary", "",
         "%d packets (%d bytes) were analysed. %d alert(s) were raised: %d high, %d medium, %d low."
         % (stats["packets"], stats["bytes"], len(alerts), sev["HIGH"], sev["MEDIUM"], sev["LOW"]), ""]
    if alerts:
        L.append("Highest-severity findings: " + "; ".join(
            "%s (%s -> %s)" % (a.rule, a.src, a.dst) for a in alerts[:3]) + ".")
        L.append("")
    L += ["## 2. Timeline of events", "", "| Time (UTC) | Severity | Event | Source | Target |",
          "|---|---|---|---|---|"]
    for a in sorted(alerts, key=lambda a: a.first_seen):
        L.append("| %s | %s | %s | %s | %s |" % (fmt_ts(a.first_seen), a.severity, a.rule, a.src, a.dst))
    L += ["", "## 3. Findings", ""]
    for i, a in enumerate(alerts, 1):
        L += ["### 3.%d %s (%s)" % (i, a.rule, a.severity), "",
              "- **Source:** %s" % a.src, "- **Target:** %s" % a.dst,
              "- **First seen:** %s" % fmt_ts(a.first_seen), "- **Last seen:** %s" % fmt_ts(a.last_seen),
              "- **Observation:** %s" % a.detail, "- **MITRE ATT&CK:** %s" % a.mitre,
              "- **Recommended action:** %s" % ADVICE.get(a.rule, "Investigate."), ""]
    if not alerts:
        L += ["No suspicious activity matched the detection rules.", ""]
    L += ["## 4. Traffic overview", "", "| Protocol | Packets |", "|---|---|"]
    L += ["| %s | %d |" % kv for kv in stats["protocols"].most_common()]
    L += ["", "Top talkers by bytes sent:", "", "| Host | Bytes |", "|---|---|"]
    L += ["| %s | %d |" % kv for kv in stats["talkers"].most_common(5)]
    L += ["", "## 5. Limitations", "",
          "Detections are threshold-based and may need tuning for the network being monitored. "
          "Only IPv4 (TCP, UDP, ICMP, ARP) traffic is analysed; encrypted payloads are not inspected.", ""]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))


def write_json(path, name, stats, alerts):
    doc = {"file": name, "packets": stats["packets"], "bytes": stats["bytes"],
           "protocols": dict(stats["protocols"]), "alerts": [asdict(a) for a in alerts]}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
