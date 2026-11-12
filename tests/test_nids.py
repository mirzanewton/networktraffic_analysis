import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from make_sample_pcap import build_sample, write_pcap  # noqa: E402
from nids.decode import decode  # noqa: E402
from nids.detectors import run_all  # noqa: E402
from nids.pcap_reader import read_packets  # noqa: E402


def load(path):
    pkts = [p for p in (decode(*r) for r in read_packets(path)) if p]
    pkts.sort(key=lambda p: p["ts"])
    return pkts


def write_pcapng(path, packets):
    def block(btype, body):
        pad = (-len(body)) % 4
        total = 12 + len(body) + pad
        return struct.pack("<II", btype, total) + body + b"\0" * pad + struct.pack("<I", total)
    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack("<HHI", 1, 0, 65535))
    for ts, frame in packets:
        us = int(ts * 1e6)
        out += block(6, struct.pack("<IIIII", 0, us >> 32, us & 0xFFFFFFFF, len(frame), len(frame)) + frame)
    with open(path, "wb") as f:
        f.write(out)


class DetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.sample = build_sample()
        cls.pcap = os.path.join(cls.tmp, "s.pcap")
        write_pcap(cls.pcap, cls.sample)

    def test_all_attacks_detected(self):
        rules = {a.rule for a in run_all(load(self.pcap))}
        for expected in ("Port scan", "Host sweep", "SYN flood", "DNS tunnelling / exfiltration",
                         "ARP spoofing", "Suspicious port", "Cleartext protocol"):
            self.assertIn(expected, rules)

    def test_no_false_positives_on_benign_traffic(self):
        benign = [(ts, f) for ts, f in self.sample if ts < 1_700_000_010.0]
        path = os.path.join(self.tmp, "benign.pcap")
        write_pcap(path, benign)
        self.assertEqual(run_all(load(path)), [])

    def test_pcapng_matches_pcap(self):
        path = os.path.join(self.tmp, "s.pcapng")
        write_pcapng(path, self.sample)
        a = {(x.rule, x.src, x.dst) for x in run_all(load(self.pcap))}
        b = {(x.rule, x.src, x.dst) for x in run_all(load(path))}
        self.assertEqual(a, b)

    def test_threshold_override(self):
        scan = [x for x in run_all(load(self.pcap), {"scan_ports": 500}) if x.rule == "Port scan"]
        self.assertEqual(scan, [])


if __name__ == "__main__":
    unittest.main()
