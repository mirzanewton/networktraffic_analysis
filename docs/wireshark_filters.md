# Wireshark display filters for verifying each detection

Use these in Wireshark to confirm what the tool flagged.

| Detection | Display filter |
|---|---|
| Port scan / SYN flood | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| Scan from one host | `ip.src == 10.0.0.66 && tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| Ping sweep | `icmp.type == 8` |
| DNS tunnelling | `dns.flags.response == 0 && frame.len > 100` |
| Long DNS names | `dns.qry.name.len > 50` |
| ARP spoofing | `arp.duplicate-address-detected \|\| arp.opcode == 2` |
| Telnet / FTP | `tcp.port == 23 \|\| tcp.port == 21` |
| Suspicious ports | `tcp.port in {4444 5555 1337 31337 6667}` |

Useful menus: **Statistics > Conversations**, **Statistics > Endpoints**, **Statistics > I/O Graphs**,
and **Analyze > Expert Information** (shows scans, retransmissions and ARP anomalies).
