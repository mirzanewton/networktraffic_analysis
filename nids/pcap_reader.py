"""Minimal readers for classic .pcap and .pcapng files (Wireshark saves pcapng by default).

read_packets(path) yields (timestamp_seconds, linktype, raw_bytes).
"""
import struct

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}


def read_packets(path):
    with open(path, "rb") as f:
        data = f.read()
    magic = data[:4]
    if magic in PCAP_MAGICS:
        yield from _read_pcap(data)
    elif magic == b"\x0a\x0d\x0d\x0a":
        yield from _read_pcapng(data)
    else:
        raise ValueError("Not a pcap/pcapng file: %s" % path)


def _read_pcap(data):
    endian, resol = PCAP_MAGICS[data[:4]]
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    pos = 24
    while pos + 16 <= len(data):
        ts_sec, ts_frac, incl, _orig = struct.unpack(endian + "IIII", data[pos:pos + 16])
        pos += 16
        raw = data[pos:pos + incl]
        pos += incl
        if len(raw) < incl:
            break  # truncated capture
        yield ts_sec + ts_frac * resol, linktype, raw


def _read_pcapng(data):
    endian = "<"
    interfaces = []  # list of (linktype, seconds_per_tick)
    pos = 0
    while pos + 12 <= len(data):
        btype = struct.unpack(endian + "I", data[pos:pos + 4])[0]
        if data[pos:pos + 4] == b"\x0a\x0d\x0d\x0a":  # Section Header Block
            bom = data[pos + 8:pos + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            interfaces = []
            btype = 0x0A0D0D0A
        blen = struct.unpack(endian + "I", data[pos + 4:pos + 8])[0]
        if blen < 12 or pos + blen > len(data):
            break
        body = data[pos + 8:pos + blen - 4]
        if btype == 1 and len(body) >= 8:  # Interface Description Block
            linktype = struct.unpack(endian + "H", body[0:2])[0]
            interfaces.append((linktype, _tsresol(body[8:], endian)))
        elif btype == 6 and len(body) >= 20:  # Enhanced Packet Block
            iface, hi, lo, caplen, _orig = struct.unpack(endian + "IIIII", body[:20])
            raw = body[20:20 + caplen]
            if iface < len(interfaces):
                linktype, tick = interfaces[iface]
                yield ((hi << 32) | lo) * tick, linktype, raw
        pos += blen


def _tsresol(opts, endian):
    """Read the if_tsresol option (code 9). Default is microseconds."""
    i = 0
    while i + 4 <= len(opts):
        code, length = struct.unpack(endian + "HH", opts[i:i + 4])
        if code == 0:
            break
        if code == 9 and length >= 1:
            v = opts[i + 4]
            return 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
        i += 4 + ((length + 3) & ~3)
    return 1e-6
