# DNS-Based Attacks

## Overview

DNS-based attacks exploit the Domain Name System for denial of service,
data exfiltration, or command-and-control (C2) communication.  DNS is
particularly attractive to attackers because it is almost always allowed
through firewalls and is often not deeply inspected.

## DNS Amplification

Uses open recursive DNS resolvers to amplify traffic toward a victim.
The attacker sends a small query with the victim's spoofed source IP;
the resolver responds with a much larger DNS response to the victim.

**Flow indicators:**
- Protocol: UDP (17)
- Port 53 (DNS)
- Large mean payload size (>512 bytes) — amplified responses
- High packet count
- Byte ratio heavily skewed (response >> query)

**MITRE ATT&CK:** T1498.002 — Reflection Amplification

## DNS Tunnelling

Encodes arbitrary data within DNS queries and responses, typically using
long subdomain labels in TXT, NULL, or CNAME records.  Used for data
exfiltration or establishing C2 channels that bypass firewalls.

**Flow indicators:**
- Protocol: UDP (17) or TCP (6)
- Port 53
- Unusually high query volume to a single domain
- Longer-than-normal DNS payload sizes
- Regular query intervals (C2 beacon pattern)
- High proportion of TXT or NULL record queries
- Subdomain labels with high entropy (base64/hex encoded data)

**MITRE ATT&CK:** T1048.003 — Exfiltration Over Alternative Protocol: DNS

## DNS Exfiltration

A specific use case of DNS tunnelling focused on extracting data from a
compromised network.  Data is encoded in subdomain labels of queries sent
to an attacker-controlled authoritative DNS server.

**Flow indicators:**
- Similar to DNS tunnelling
- High outbound query volume
- Large cumulative byte count over many small queries
- Queries to unusual or recently registered domains

**MITRE ATT&CK:** T1048.003

## DNS Cache Poisoning (Pharming)

Injects forged DNS responses to redirect traffic to attacker-controlled
servers.  Primarily detected by observing unexpected DNS response patterns
or duplicate/conflicting responses.

**Flow indicators:**
- Protocol: UDP (17), port 53
- Multiple responses for the same query with different answers
- Responses arriving before or shortly after the legitimate response

**MITRE ATT&CK:** T1557.004 — DNS Spoofing

## Detection Considerations

- DNS flows are typically UDP on port 53 but may use TCP for zone transfers
  or large responses
- Normal DNS traffic is characterised by small queries (<100 bytes) and
  moderate responses (<512 bytes for non-DNSSEC)
- Anomalous DNS traffic often has disproportionate payload sizes or volumes
- The LLM should flag any sustained DNS flow with high byte counts or
  unusually large payloads for further investigation
