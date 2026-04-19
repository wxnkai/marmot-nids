# Port Scanning Techniques

## Overview

Port scanning is a reconnaissance technique used to discover open ports, running
services, and firewall configurations on a target host.  Different scan types
vary in stealth, accuracy, and the TCP flags they use.

## TCP SYN Scan (Half-Open Scan)

The most common scan type.  Sends SYN packets and observes the response:
- SYN-ACK → port is open
- RST → port is closed
- No response → port is filtered

**Flow indicators:**
- Protocol: TCP (6)
- Many distinct destination ports from a single source
- Each flow has very few packets (1-3) — connection never completes
- High SYN count with zero or very low ACK count
- Short flow duration

**MITRE ATT&CK:** T1046 — Network Service Scanning

## TCP NULL Scan

Sends TCP packets with no flags set (flags = 0x00).  RFC 793-compliant hosts
respond with RST to closed ports and silently drop packets on open ports.

**Flow indicators:**
- Protocol: TCP (6)
- All TCP flag counts are zero (SYN=0, ACK=0, FIN=0, RST=0, PSH=0, URG=0)
- Typically targets multiple ports from the same source

**MITRE ATT&CK:** T1046

## TCP FIN Scan

Sends packets with only the FIN flag set, without a prior SYN handshake.
Similar to NULL scan in evasion capability — bypasses some stateless firewalls.

**Flow indicators:**
- Protocol: TCP (6)
- FIN count >= 1
- SYN count = 0, ACK count = 0, RST count = 0
- Multiple destination ports targeted

**MITRE ATT&CK:** T1046

## TCP XMAS Scan

Sends packets with FIN, PSH, and URG flags simultaneously set (the "Christmas
tree" pattern).  Named for the three flags being "lit up" like a Christmas tree.

**Flow indicators:**
- Protocol: TCP (6)
- FIN count >= 1, PSH count >= 1, URG count >= 1
- SYN count = 0, ACK count = 0
- Multiple destination ports

**MITRE ATT&CK:** T1046

## UDP Scan

Sends UDP datagrams to target ports.  If ICMP Destination Unreachable is
returned, the port is closed.  No response may indicate open or filtered.

**Flow indicators:**
- Protocol: UDP (17)
- Many distinct destination ports from a single source
- Very small payload sizes
- Short flow durations

**MITRE ATT&CK:** T1046

## Detection Considerations

Port scans may be:
- **Vertical**: one source IP scanning many ports on one target
- **Horizontal**: one source IP scanning one port across many targets
- **Slow**: deliberately low-rate scanning to evade threshold-based detection

Low-and-slow scans are particularly challenging because individual flows look
benign.  The LLM should consider correlation across multiple flows from the
same source IP when evaluating scan activity.
