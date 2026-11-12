"""Detection rules. Each rule looks at decoded packets and returns Alert objects."""
import math
from collections import Counter, defaultdict, deque
from dataclasses import dataclass

from .decode import is_syn_only

DEFAULTS = {
    "scan_ports": 15,          # distinct ports on one host ...
    "scan_window": 10.0,       # ... within this many seconds
    "sweep_hosts": 10,         # distinct hosts probed on one port / by ping ...
    "sweep_window": 10.0,      # ... within this many seconds
    "syn_flood_count": 100,    # SYN-only packets to one host ...
    "syn_flood_window": 5.0,   # ... within this many seconds
    "dns_min_queries": 5,      # suspicious queries to one parent domain
    "dns_name_len": 60,        # query name length considered suspicious
    "dns_label_len": 40,       # single label length considered suspicious
    "dns_entropy": 3.6,        # Shannon entropy of subdomain part
}

SUSPICIOUS_PORTS = {4444: "Metasploit default", 5555: "common backdoor", 1337: "common backdoor",
                    31337: "Back Orifice / elite", 6667: "IRC (botnet C2)"}
CLEARTEXT_PORTS = {21: "FTP", 23: "Telnet"}
SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


@dataclass
class Alert:
    rule: str
    severity: str
    src: str
    dst: str
    first_seen: float
    last_seen: float
    detail: str
    mitre: str = ""


def burst(events, window, threshold):
    """events: time-sorted [(ts, item)]. Return (start, end, n_distinct) for the first
    sliding window holding >= threshold distinct items, else None."""
    dq, cnt = deque(), Counter()
    for ts, item in events:
        dq.append((ts, item))
        cnt[item] += 1
        while ts - dq[0][0] > window:
            _, old = dq.popleft()
            cnt[old] -= 1
            if cnt[old] == 0:
                del cnt[old]
        if len(cnt) >= threshold:
            return dq[0][0], ts, len(cnt)
    return None


def entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def port_scan(pkts, cfg):
    groups = defaultdict(list)
    for p in pkts:
        if is_syn_only(p):
            groups[(p["src"], p["dst"])].append((p["ts"], p["dport"]))
    for (src, dst), ev in groups.items():
        hit = burst(ev, cfg["scan_window"], cfg["scan_ports"])
        if hit:
            yield Alert("Port scan", "HIGH", src, dst, hit[0], hit[1],
                        "%d distinct TCP ports probed with SYN-only packets in %.1fs."
                        % (hit[2], hit[1] - hit[0]), "T1046 Network Service Discovery")


def host_sweep(pkts, cfg):
    groups = defaultdict(list)
    for p in pkts:
        if is_syn_only(p):
            groups[(p["src"], "TCP/%d" % p["dport"])].append((p["ts"], p["dst"]))
        elif p["proto"] == "ICMP" and p["icmp_type"] == 8:
            groups[(p["src"], "ICMP echo")].append((p["ts"], p["dst"]))
    for (src, what), ev in groups.items():
        hit = burst(ev, cfg["sweep_window"], cfg["sweep_hosts"])
        if hit:
            yield Alert("Host sweep", "MEDIUM", src, "%d hosts" % hit[2], hit[0], hit[1],
                        "%s sent to %d distinct hosts in %.1fs (network discovery)."
                        % (what, hit[2], hit[1] - hit[0]), "T1018 Remote System Discovery")


def syn_flood(pkts, cfg):
    groups = defaultdict(list)
    srcs = defaultdict(set)
    for i, p in enumerate(pkts):
        if is_syn_only(p):
            groups[(p["dst"], p["dport"])].append((p["ts"], i))
            srcs[(p["dst"], p["dport"])].add(p["src"])
    for (dst, dport), ev in groups.items():
        hit = burst(ev, cfg["syn_flood_window"], cfg["syn_flood_count"])
        if hit:
            n = len(srcs[(dst, dport)])
            yield Alert("SYN flood", "HIGH", "%d sources" % n, "%s:%d" % (dst, dport),
                        hit[0], hit[1],
                        "%d SYN-only packets in %.1fs from %d source address(es); likely "
                        "denial-of-service (sources may be spoofed)." % (hit[2], hit[1] - hit[0], n),
                        "T1498 Network Denial of Service")


def dns_tunnel(pkts, cfg):
    groups = defaultdict(list)
    for p in pkts:
        name = p.get("dns_query")
        if not name:
            continue
        labels = name.split(".")
        sub = ".".join(labels[:-2])
        suspicious = (len(name) >= cfg["dns_name_len"]
                      or max(len(l) for l in labels) >= cfg["dns_label_len"]
                      or (len(sub) >= 20 and entropy(sub.replace(".", "")) >= cfg["dns_entropy"]))
        if suspicious:
            groups[(p["src"], ".".join(labels[-2:]))].append((p["ts"], name))
    for (src, parent), ev in groups.items():
        if len(ev) >= cfg["dns_min_queries"]:
            yield Alert("DNS tunnelling / exfiltration", "HIGH", src, parent, ev[0][0], ev[-1][0],
                        "%d long or high-entropy DNS queries to %s (e.g. %s)."
                        % (len(ev), parent, ev[0][1][:70]), "T1071.004 Application Layer Protocol: DNS")


def arp_spoof(pkts, cfg):
    seen = defaultdict(dict)  # ip -> {mac: first_ts}
    last = {}
    for p in pkts:
        if p["proto"] == "ARP" and p["arp_op"] in (1, 2) and p["src"] != "0.0.0.0":
            seen[p["src"]].setdefault(p["src_mac"], p["ts"])
            last[p["src"]] = p["ts"]
    for ip, macs in seen.items():
        if len(macs) > 1:
            yield Alert("ARP spoofing", "HIGH", ", ".join(sorted(macs)), ip,
                        min(macs.values()), last[ip],
                        "IP %s is claimed by %d different MAC addresses (possible man-in-the-middle)."
                        % (ip, len(macs)), "T1557.002 ARP Cache Poisoning")


def suspicious_ports(pkts, cfg):
    seen = {}
    for p in pkts:
        if is_syn_only(p) and p["dport"] in SUSPICIOUS_PORTS:
            key = (p["src"], p["dst"], p["dport"])
            seen.setdefault(key, [p["ts"], p["ts"]])[1] = p["ts"]
    for (src, dst, port), (t0, t1) in seen.items():
        yield Alert("Suspicious port", "MEDIUM", src, "%s:%d" % (dst, port), t0, t1,
                    "Connection attempt to port %d (%s)." % (port, SUSPICIOUS_PORTS[port]),
                    "T1571 Non-Standard Port")


def cleartext(pkts, cfg):
    seen = {}
    for p in pkts:
        if is_syn_only(p) and p["dport"] in CLEARTEXT_PORTS:
            key = (p["src"], p["dst"], p["dport"])
            seen.setdefault(key, [p["ts"], p["ts"]])[1] = p["ts"]
    for (src, dst, port), (t0, t1) in seen.items():
        yield Alert("Cleartext protocol", "LOW", src, "%s:%d" % (dst, port), t0, t1,
                    "%s session attempted; credentials and data travel unencrypted."
                    % CLEARTEXT_PORTS[port], "T1040 Network Sniffing")


RULES = [port_scan, host_sweep, syn_flood, dns_tunnel, arp_spoof, suspicious_ports, cleartext]


def run_all(pkts, overrides=None):
    cfg = dict(DEFAULTS, **(overrides or {}))
    alerts = []
    for rule in RULES:
        alerts.extend(rule(pkts, cfg))
    alerts.sort(key=lambda a: (SEV_ORDER[a.severity], a.first_seen))
    return alerts
