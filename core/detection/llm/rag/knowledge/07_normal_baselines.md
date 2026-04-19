# Normal Baseline Traffic Patterns

## Overview

Understanding normal traffic patterns is essential for reducing false positives.
Many legitimate network activities produce flows that resemble attack traffic
unless their context is considered.

## Normal TCP Connection Lifecycle

A healthy TCP connection follows the three-way handshake:
1. Client → Server: SYN
2. Server → Client: SYN-ACK
3. Client → Server: ACK

This produces a SYN ratio of approximately 0.15-0.33 in a short flow
(1 SYN out of 3-6 packets for the handshake + initial data).

**Key indicators of normal TCP:**
- SYN ratio < 0.5 (roughly half or fewer packets are SYN)
- ACK count > 0 (handshake completed)
- Balanced bidirectional traffic (both sides sending data)
- FIN packets present at the end (clean connection shutdown)

## Normal HTTP/HTTPS Traffic

Web browsing produces flows with:
- Destination port 80 (HTTP) or 443 (HTTPS)
- Moderate packet counts (10-100 per page load)
- Variable payload sizes (small requests, larger responses)
- Duration typically 1-30 seconds per page load
- Multiple parallel flows to the same server (CSS, JS, images)

**Not suspicious:** High packet count on port 443 with large response
payloads — this is likely a file download or streaming content.

## Normal DNS Traffic

Typical DNS resolution:
- Protocol: UDP (17), port 53
- Very short flows (1-2 packets: query + response)
- Small payload sizes (query < 100 bytes, response < 512 bytes)
- Low frequency per source (a few queries per second at most)

**Not suspicious:** Periodic DNS queries at regular intervals —
this is likely health-check monitoring or service discovery.

## Normal SSH Sessions

Legitimate interactive SSH sessions:
- Protocol: TCP (6), port 22
- Long duration (minutes to hours)
- Moderate packet count relative to duration
- Bidirectional traffic (typing + responses)
- IAT varies widely (human typing pauses)

**Key differentiator from brute force:** Long duration with moderate
packet rate, versus short duration with high packet rate.

## Normal ICMP Traffic

Routine monitoring (ping, traceroute):
- Protocol: ICMP (1)
- Low packet count (4-10 packets for a typical ping)
- Regular IAT (~1 second between pings)
- Standard payload size (56 bytes for Unix ping, 32 for Windows)

**Not suspicious:** Small numbers of ICMP echo requests with ~1s IAT.

## Internal Network Baselines

Common patterns that may look suspicious but are normal:
- **DHCP**: Broadcast traffic on UDP 67/68
- **NTP**: Small UDP flows to port 123 at regular intervals
- **SNMP**: UDP port 161/162 for network management
- **Windows domain traffic**: SMB on 445, Kerberos on 88, LDAP on 389
- **DNS internal resolvers**: High query volume from dedicated resolvers

## False Positive Reduction Guidelines

When evaluating flows, the LLM should consider:

1. **Volume context**: 100 packets to port 80 over 30 seconds is normal
   web browsing, not a brute force attack
2. **Bidirectionality**: Attack flows often lack response traffic
   (SYN flood has no ACK; scans get few responses)
3. **Duration**: Legitimate connections tend to be longer-lived than
   attack flows (except for legitimate web API calls)
4. **Payload size distribution**: Normal traffic has variable payload
   sizes; attacks often have uniform sizes
5. **Protocol appropriateness**: SMB traffic between file servers is
   expected; SMB from a web server to a workstation is suspicious
