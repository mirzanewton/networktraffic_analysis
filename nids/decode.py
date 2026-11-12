"""Decode raw frames into simple dicts (Ethernet/VLAN, IPv4, ARP, TCP, UDP, ICMP, DNS queries)."""
import socket
import struct

SYN, RST, ACK = 0x02, 0x04, 0x10


def _ip(b):
    return socket.inet_ntoa(b)


def _mac(b):
    return ":".join("%02x" % x for x in b)


def parse_dns_query(payload):
    """Return the queried name for a DNS *query* packet, else None."""
    if len(payload) < 12:
        return None
    flags, qd = struct.unpack("!HH", payload[2:6])
    if flags & 0x8000 or qd < 1:
        return None
    i, labels = 12, []
    while i < len(payload):
        n = payload[i]
        if n == 0:
            break
        if n & 0xC0 or i + 1 + n > len(payload):
            return None
        labels.append(payload[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    return ".".join(labels) if labels else None


def decode(ts, linktype, raw):
    """Return a dict describing the packet, or None if it is not something we analyse."""
    pkt = {"ts": ts, "len": len(raw), "proto": "OTHER"}
    off = 0
    if linktype == 1:  # Ethernet
        if len(raw) < 14:
            return None
        ethertype = struct.unpack("!H", raw[12:14])[0]
        pkt["src_mac"] = _mac(raw[6:12])
        off = 14
        while ethertype in (0x8100, 0x88A8):  # VLAN tags
            if len(raw) < off + 4:
                return None
            ethertype = struct.unpack("!H", raw[off + 2:off + 4])[0]
            off += 4
    elif linktype == 101:  # raw IP
        ethertype = 0x0800
    elif linktype == 113:  # Linux cooked capture
        if len(raw) < 16:
            return None
        ethertype = struct.unpack("!H", raw[14:16])[0]
        off = 16
    else:
        return None

    if ethertype == 0x0806:  # ARP
        if len(raw) < off + 28:
            return None
        op = struct.unpack("!H", raw[off + 6:off + 8])[0]
        pkt.update(proto="ARP", arp_op=op, src_mac=_mac(raw[off + 8:off + 14]),
                   src=_ip(raw[off + 14:off + 18]), dst=_ip(raw[off + 24:off + 28]))
        return pkt
    if ethertype != 0x0800:
        return None

    ip = raw[off:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    proto = ip[9]
    frag = struct.unpack("!H", ip[6:8])[0] & 0x1FFF
    pkt.update(src=_ip(ip[12:16]), dst=_ip(ip[16:20]), ttl=ip[8], proto="IP")
    if frag or len(ip) < ihl:
        return pkt
    l4 = ip[ihl:]

    if proto == 6 and len(l4) >= 20:
        sport, dport = struct.unpack("!HH", l4[:4])
        pkt.update(proto="TCP", sport=sport, dport=dport, flags=l4[13])
    elif proto == 17 and len(l4) >= 8:
        sport, dport = struct.unpack("!HH", l4[:4])
        pkt.update(proto="UDP", sport=sport, dport=dport)
        if dport == 53:
            name = parse_dns_query(l4[8:])
            if name:
                pkt["dns_query"] = name
    elif proto == 1 and len(l4) >= 2:
        pkt.update(proto="ICMP", icmp_type=l4[0])
    return pkt


def is_syn_only(pkt):
    return pkt.get("proto") == "TCP" and pkt["flags"] & (SYN | ACK) == SYN
