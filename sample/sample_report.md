# Network Security Incident Report

**Capture analysed:** `sample/sample.pcap`  
**Capture window:** 2023-11-14 22:13:20 UTC to 2023-11-14 22:14:21 UTC  
**Report generated:** 2026-11-12 18:37:09 UTC  
**Tool:** nids (pure-Python traffic analysis and intrusion detection)

## 1. Executive summary

752 packets (42966 bytes) were analysed. 9 alert(s) were raised: 4 high, 2 medium, 3 low.

Highest-severity findings: ARP spoofing (aa:00:00:00:00:01, de:ad:be:ef:00:66 -> 10.0.0.1); Port scan (10.0.0.66 -> 10.0.0.5); SYN flood (201 sources -> 10.0.0.5:80).

## 2. Timeline of events

| Time (UTC) | Severity | Event | Source | Target |
|---|---|---|---|---|
| 2023-11-14 22:13:21 UTC | HIGH | ARP spoofing | aa:00:00:00:00:01, de:ad:be:ef:00:66 | 10.0.0.1 |
| 2023-11-14 22:13:30 UTC | HIGH | Port scan | 10.0.0.66 | 10.0.0.5 |
| 2023-11-14 22:13:30 UTC | LOW | Cleartext protocol | 10.0.0.66 | 10.0.0.5:21 |
| 2023-11-14 22:13:31 UTC | LOW | Cleartext protocol | 10.0.0.66 | 10.0.0.5:23 |
| 2023-11-14 22:13:40 UTC | MEDIUM | Host sweep | 10.0.0.66 | 10 hosts |
| 2023-11-14 22:13:50 UTC | HIGH | SYN flood | 201 sources | 10.0.0.5:80 |
| 2023-11-14 22:14:00 UTC | HIGH | DNS tunnelling / exfiltration | 10.0.0.23 | evil-example.com |
| 2023-11-14 22:14:20 UTC | LOW | Cleartext protocol | 10.0.0.23 | 10.0.0.5:23 |
| 2023-11-14 22:14:21 UTC | MEDIUM | Suspicious port | 10.0.0.23 | 10.0.0.50:4444 |

## 3. Findings

### 3.1 ARP spoofing (HIGH)

- **Source:** aa:00:00:00:00:01, de:ad:be:ef:00:66
- **Target:** 10.0.0.1
- **First seen:** 2023-11-14 22:13:21 UTC
- **Last seen:** 2023-11-14 22:14:14 UTC
- **Observation:** IP 10.0.0.1 is claimed by 2 different MAC addresses (possible man-in-the-middle).
- **MITRE ATT&CK:** T1557.002 ARP Cache Poisoning
- **Recommended action:** Enable dynamic ARP inspection / port security; locate the rogue MAC on the switch.

### 3.2 Port scan (HIGH)

- **Source:** 10.0.0.66
- **Target:** 10.0.0.5
- **First seen:** 2023-11-14 22:13:30 UTC
- **Last seen:** 2023-11-14 22:13:30 UTC
- **Observation:** 15 distinct TCP ports probed with SYN-only packets in 0.7s.
- **MITRE ATT&CK:** T1046 Network Service Discovery
- **Recommended action:** Block or rate-limit the source at the firewall; check the target for exposed services.

### 3.3 SYN flood (HIGH)

- **Source:** 201 sources
- **Target:** 10.0.0.5:80
- **First seen:** 2023-11-14 22:13:50 UTC
- **Last seen:** 2023-11-14 22:13:50 UTC
- **Observation:** 100 SYN-only packets in 0.5s from 201 source address(es); likely denial-of-service (sources may be spoofed).
- **MITRE ATT&CK:** T1498 Network Denial of Service
- **Recommended action:** Enable SYN cookies and rate limiting; engage the upstream provider if the flood continues.

### 3.4 DNS tunnelling / exfiltration (HIGH)

- **Source:** 10.0.0.23
- **Target:** evil-example.com
- **First seen:** 2023-11-14 22:14:00 UTC
- **Last seen:** 2023-11-14 22:14:06 UTC
- **Observation:** 14 long or high-entropy DNS queries to evil-example.com (e.g. 2073fec8df4f50947aaeb26c57d21fa5d328263dfe574de7.t.evil-example.com).
- **MITRE ATT&CK:** T1071.004 Application Layer Protocol: DNS
- **Recommended action:** Block the domain, inspect the source host for malware, and review data leaving via DNS.

### 3.5 Host sweep (MEDIUM)

- **Source:** 10.0.0.66
- **Target:** 10 hosts
- **First seen:** 2023-11-14 22:13:40 UTC
- **Last seen:** 2023-11-14 22:13:40 UTC
- **Observation:** ICMP echo sent to 10 distinct hosts in 0.9s (network discovery).
- **MITRE ATT&CK:** T1018 Remote System Discovery
- **Recommended action:** Investigate the source host for compromise; restrict ICMP and lateral traffic between segments.

### 3.6 Suspicious port (MEDIUM)

- **Source:** 10.0.0.23
- **Target:** 10.0.0.50:4444
- **First seen:** 2023-11-14 22:14:21 UTC
- **Last seen:** 2023-11-14 22:14:21 UTC
- **Observation:** Connection attempt to port 4444 (Metasploit default).
- **MITRE ATT&CK:** T1571 Non-Standard Port
- **Recommended action:** Identify the process behind the connection and check for backdoors or C2 beacons.

### 3.7 Cleartext protocol (LOW)

- **Source:** 10.0.0.66
- **Target:** 10.0.0.5:21
- **First seen:** 2023-11-14 22:13:30 UTC
- **Last seen:** 2023-11-14 22:13:30 UTC
- **Observation:** FTP session attempted; credentials and data travel unencrypted.
- **MITRE ATT&CK:** T1040 Network Sniffing
- **Recommended action:** Replace with SSH / SFTP / FTPS and disable the legacy service.

### 3.8 Cleartext protocol (LOW)

- **Source:** 10.0.0.66
- **Target:** 10.0.0.5:23
- **First seen:** 2023-11-14 22:13:31 UTC
- **Last seen:** 2023-11-14 22:13:31 UTC
- **Observation:** Telnet session attempted; credentials and data travel unencrypted.
- **MITRE ATT&CK:** T1040 Network Sniffing
- **Recommended action:** Replace with SSH / SFTP / FTPS and disable the legacy service.

### 3.9 Cleartext protocol (LOW)

- **Source:** 10.0.0.23
- **Target:** 10.0.0.5:23
- **First seen:** 2023-11-14 22:14:20 UTC
- **Last seen:** 2023-11-14 22:14:20 UTC
- **Observation:** Telnet session attempted; credentials and data travel unencrypted.
- **MITRE ATT&CK:** T1040 Network Sniffing
- **Recommended action:** Replace with SSH / SFTP / FTPS and disable the legacy service.

## 4. Traffic overview

| Protocol | Packets |
|---|---|
| TCP | 622 |
| UDP | 94 |
| ICMP | 30 |
| ARP | 6 |

Top talkers by bytes sent:

| Host | Bytes |
|---|---|
| 10.0.0.23 | 4651 |
| 10.0.0.66 | 4500 |
| 10.0.0.21 | 3129 |
| 10.0.0.22 | 2578 |
| 10.0.0.25 | 2202 |

## 5. Limitations

Detections are threshold-based and may need tuning for the network being monitored. Only IPv4 (TCP, UDP, ICMP, ARP) traffic is analysed; encrypted payloads are not inspected.
