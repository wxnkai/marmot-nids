# MITRE ATT&CK Network-Based Techniques

## Overview

The MITRE ATT&CK framework catalogues adversary tactics, techniques, and
procedures (TTPs).  This reference maps network-observable techniques to
their ATT&CK identifiers for use in alert classification.

## Reconnaissance (TA0043)

### T1046 — Network Service Scanning
Scanning target hosts for open ports and running services.

**Network indicators:** SYN scan, NULL scan, FIN scan, XMAS scan, UDP scan.
Multiple short-lived flows to many ports from a single source.

## Initial Access (TA0001)

### T1190 — Exploit Public-Facing Application
Exploiting vulnerabilities in internet-facing applications (SQLi, command
injection, file upload exploits).

**Network indicators:** Sustained HTTP traffic to specific endpoints with
unusual payload patterns.

## Execution (TA0002)

### T1059 — Command and Scripting Interpreter
Executing commands on compromised hosts via various interpreters.

**Sub-techniques relevant to network detection:**
- T1059.007 — JavaScript (XSS)

### T1047 — Windows Management Instrumentation
Remote command execution via WMI/DCOM.

**Network indicators:** TCP connections to port 135 followed by high-port
connections.

## Credential Access (TA0006)

### T1110 — Brute Force
Systematic password guessing against authentication services.

**Sub-techniques:**
- T1110.001 — Password Guessing (SSH, RDP, FTP, HTTP login)
- T1110.003 — Password Spraying (one password, many accounts)
- T1110.004 — Credential Stuffing (reusing breached credentials)

**Network indicators:** Many connection attempts to authentication ports
(22, 3389, 21, 80, 443) in a short window.

## Lateral Movement (TA0008)

### T1021 — Remote Services
Using remote services for lateral movement.

**Sub-techniques:**
- T1021.001 — Remote Desktop Protocol (port 3389)
- T1021.002 — SMB/Windows Admin Shares (port 445)
- T1021.004 — SSH (port 22)
- T1021.006 — Windows Remote Management (WinRM, port 5985/5986)

**Network indicators:** Internal-to-internal flows on administrative ports.

## Command and Control (TA0011)

### T1095 — Non-Application Layer Protocol
Using ICMP, UDP, or raw sockets for C2 communication.

**Network indicators:** Large ICMP payloads, unusual ICMP types, regular
beacon intervals.

### T1071 — Application Layer Protocol
Hiding C2 in legitimate protocols (HTTP, HTTPS, DNS).

**Network indicators:** Regular beacon intervals, consistent payload sizes,
unusual URLs or DNS query patterns.

## Exfiltration (TA0010)

### T1048 — Exfiltration Over Alternative Protocol
Exfiltrating data over non-standard protocols.

**Sub-techniques:**
- T1048.003 — Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol (DNS tunnelling, ICMP tunnelling)

**Network indicators:** High outbound volume over DNS or ICMP, encoded
subdomain labels, large cumulative byte counts.

## Impact (TA0040)

### T1498 — Network Denial of Service
Flooding targets with traffic to cause service disruption.

**Sub-techniques:**
- T1498.001 — Direct Network Flood (SYN, ICMP, UDP, RST flood)
- T1498.002 — Reflection Amplification (DNS, NTP, SSDP reflection)

**Network indicators:** Extremely high packet rates, low IAT, protocol-
specific ratio anomalies (SYN ratio, RST ratio).

## Mapping Guide for the LLM

When generating alerts, use the most specific technique ID available:
1. If the attack uses a specific protocol variant, use the sub-technique
   (e.g., T1498.001 for SYN flood, not just T1498)
2. If uncertain about the specific variant, use the parent technique
3. If no MITRE mapping applies, set mitre_technique to null
4. Cross-reference with the severity: Critical and High alerts should
   almost always have a MITRE mapping
