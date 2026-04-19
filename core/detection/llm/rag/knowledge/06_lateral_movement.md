# Lateral Movement Indicators

## Overview

Lateral movement refers to techniques attackers use to move through a
network after gaining an initial foothold, typically to find and access
high-value targets (domain controllers, databases, file servers).

## SMB-Based Lateral Movement

Server Message Block (SMB) on port 445 is commonly used for lateral
movement in Windows environments.  Attackers use tools like PsExec,
Impacket, and Cobalt Strike to move between hosts.

**Flow indicators:**
- Protocol: TCP (6)
- Destination port 445 (SMB)
- Short-lived connections to many internal hosts from the same source
- Small packet exchanges (authentication + command execution)

**MITRE ATT&CK:** T1021.002 — SMB/Windows Admin Shares

## WMI-Based Lateral Movement

Windows Management Instrumentation (WMI) can execute commands remotely
via DCOM on port 135 or dynamically allocated high ports.

**Flow indicators:**
- Protocol: TCP (6)
- Initial connection to port 135 (RPC endpoint mapper)
- Followed by connections to high ports (>1024) on the same target
- Multiple such patterns from a single source

**MITRE ATT&CK:** T1047 — Windows Management Instrumentation

## RDP-Based Lateral Movement

Legitimate RDP sessions are common in enterprise networks, but unusual
RDP patterns may indicate compromise.

**Flow indicators:**
- Protocol: TCP (6)
- Destination port 3389
- RDP from a server to a workstation (unusual direction)
- RDP sessions originating from hosts that don't normally use RDP
- High-volume data transfer within RDP sessions (file exfiltration)

**MITRE ATT&CK:** T1021.001 — Remote Desktop Protocol

## SSH-Based Lateral Movement

SSH tunnels and remote command execution via port 22.

**Flow indicators:**
- Protocol: TCP (6)
- Destination port 22
- Internal-to-internal SSH sessions (east-west traffic)
- SSH sessions from hosts not in the normal SSH bastion list
- Large byte counts (potential tunnelling or file transfer)

**MITRE ATT&CK:** T1021.004 — SSH

## Detection Considerations

Lateral movement is often characterised by:
- East-west traffic patterns (internal host to internal host)
- Sequential connections to multiple internal hosts from the same source
- Use of administrative protocols (SMB, WMI, RDP, SSH, WinRM)
- Time-of-day anomalies (connections at unusual hours)
- Newly observed source-destination pairs for administrative protocols

The LLM should pay attention to internal IP ranges communicating on
administrative ports, especially when combined with:
- Short flow durations (automated tool behaviour)
- Low packet counts (quick command execution)
- Multiple targets from the same source in rapid succession
