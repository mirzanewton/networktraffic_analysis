# Incident Report Template

**Incident ID:**
**Date / time detected:**
**Analyst:**
**Severity:** Low / Medium / High / Critical

## 1. Summary
One paragraph: what happened, which systems were affected, current status.

## 2. Evidence
- Capture file(s) and hash (`certutil -hashfile capture.pcapng SHA256` on Windows)
- Tool output (`alerts.json`, `incident_report.md`)
- Wireshark filters used to confirm

## 3. Timeline
| Time (UTC) | Event | Source | Target |
|---|---|---|---|

## 4. Analysis
Attack technique (map to MITRE ATT&CK), indicators of compromise (IPs, domains, ports, MACs), impact.

## 5. Containment and remediation
Actions taken and still required.

## 6. Lessons learned
Detection gaps, tuning changes, hardening steps.
