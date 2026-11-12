"""Generate a synthetic lab capture (benign traffic + simulated attacks) so the tool can be
demonstrated without Wireshark. Everything here is fake traffic written to a file; nothing
is sent on the network.

    python make_sample_pcap.py            # writes sample/sample.pcap
"""
import os
import random
import struct

BASE = 1_700_000_000.0
GW, SERVER, ATTACKER = "10.0.0.1", "10.0.0.5", "10.0.0.66"
MACS = {GW: "aa:00:00:00:00:01", SERVER: "aa:00:00:00:00:05", ATTACKER: "de:ad:be:ef:00:66"}


def mac(s):
    return bytes(int(x, 16) for x in s.split(":"))


def ip(s):
    return bytes(int(x) for x in s.split("."))


def eth(src_mac, dst_mac, ethertype, payload):
    return mac(dst_mac) + mac(src_mac) + struct.pack("!H", ethertype) + payload


def ipv4(src, dst, proto, payload):
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(payload), 0, 0x4000, 64, proto, 0) + ip(src) + ip(dst)
    return hdr + payload


def tcp(sport, dport, flags):
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 64240, 0, 0)


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def dns_query(name, txid=1):
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)


def arp(op, smac, sip, tmac, tip):
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + mac(smac) + ip(sip) + mac(tmac) + ip(tip)


def frame_tcp(src, dst, sport, dport, flags):
    return eth(MACS.get(src, "aa:bb:cc:00:00:99"), MACS.get(dst, MACS[GW]), 0x0800,
               ipv4(src, dst, 6, tcp(sport, dport, flags)))


def build_sample(seed=7):
    rnd = random.Random(seed)
    pk = []  # (ts, frame)
    t = BASE

    # --- Benign background: web, DNS, ping ------------------------------------------------
    clients = ["10.0.0.%d" % n for n in range(20, 26)]
    sites = ["www.example.com", "mail.example.com", "updates.example.org", "cdn.example.net"]
    for _ in range(80):
        t += rnd.uniform(0.05, 0.6)
        c = rnd.choice(clients)
        pk.append((t, eth("aa:bb:cc:00:00:%02x" % int(c.split(".")[-1]), MACS[GW], 0x0800,
                          ipv4(c, "10.0.0.2", 17, udp(40000 + rnd.randint(0, 999), 53,
                                                       dns_query(rnd.choice(sites), rnd.randint(1, 65000)))))))
        pk.append((t + 0.01, frame_tcp(c, "198.51.100.10", 50000 + rnd.randint(0, 999), 443, 0x02)))
        pk.append((t + 0.02, frame_tcp(c, "198.51.100.10", 50000 + rnd.randint(0, 999), 443, 0x10)))
    # Normal ARP
    pk.append((BASE + 1, eth(MACS[GW], "ff:ff:ff:ff:ff:ff", 0x0806, arp(1, MACS[GW], GW, "00:00:00:00:00:00", "10.0.0.20"))))

    # --- Attack 1: port scan (attacker -> server, ports 1-60 at ~20/s) --------------------
    t = BASE + 10
    for port in range(1, 61):
        pk.append((t, frame_tcp(ATTACKER, SERVER, 45000, port, 0x02)))
        t += 0.05

    # --- Attack 2: ping sweep across the subnet ---------------------------------------------
    t = BASE + 20
    for host in range(1, 31):
        icmp = struct.pack("!BBHHH", 8, 0, 0, 1, host)
        pk.append((t, eth(MACS[ATTACKER], MACS[GW], 0x0800, ipv4(ATTACKER, "10.0.0.%d" % host, 1, icmp))))
        t += 0.1

    # --- Attack 3: SYN flood from many spoofed sources ----------------------------------------
    t = BASE + 30
    for i in range(400):
        src = "203.0.113.%d" % rnd.randint(1, 254)
        pk.append((t, frame_tcp(src, SERVER, rnd.randint(1024, 65000), 80, 0x02)))
        t += 0.005

    # --- Attack 4: DNS tunnelling (hex-encoded data in subdomains) -------------------------
    t = BASE + 40
    for i in range(14):
        sub = "".join(rnd.choice("0123456789abcdef") for _ in range(48))
        pk.append((t, eth("aa:bb:cc:00:00:17", MACS[GW], 0x0800,
                          ipv4("10.0.0.23", "10.0.0.2", 17, udp(53000 + i, 53, dns_query(sub + ".t.evil-example.com", 900 + i))))))
        t += 0.5

    # --- Attack 5: ARP spoofing (attacker claims to be the gateway) -------------------------
    t = BASE + 50
    for i in range(5):
        pk.append((t, eth(MACS[ATTACKER], MACS["10.0.0.5"], 0x0806, arp(2, MACS[ATTACKER], GW, MACS[SERVER], SERVER))))
        t += 1

    # --- Misc: telnet attempt and a connection to the Metasploit default port -------------
    pk.append((BASE + 60, frame_tcp("10.0.0.23", SERVER, 51000, 23, 0x02)))
    pk.append((BASE + 61, frame_tcp("10.0.0.23", "10.0.0.50", 51001, 4444, 0x02)))

    pk.sort(key=lambda x: x[0])
    return pk


def write_pcap(path, packets):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in packets:
            sec = int(ts)
            f.write(struct.pack("<IIII", sec, int((ts - sec) * 1e6), len(frame), len(frame)))
            f.write(frame)


if __name__ == "__main__":
    out = os.path.join("sample", "sample.pcap")
    os.makedirs("sample", exist_ok=True)
    write_pcap(out, build_sample())
    print("Wrote %s" % out)
