# DoS and DDoS Attack Patterns

## Overview

Denial-of-Service (DoS) and Distributed Denial-of-Service (DDoS) attacks aim to
exhaust resources on a target system — CPU, memory, connection tables, or network
bandwidth — rendering the target unable to serve legitimate users.

## SYN Flood

A SYN flood exploits the TCP three-way handshake by sending large volumes of SYN
packets without completing the handshake (no ACK response).  Each half-open connection
consumes a slot in the target's connection table.

**Flow indicators:**
- Protocol: TCP (6)
- Very high packet count in a short duration
- SYN ratio near 1.0 (almost all packets are SYN, very few ACK)
- Mean IAT near zero (high packet rate)
- Small or zero payload length (SYN packets carry no data)

**MITRE ATT&CK:** T1498.001 — Direct Network Flood

## RST Flood

An RST flood injects forged TCP RST packets to forcibly terminate established
connections between a target and its legitimate peers.

**Flow indicators:**
- Protocol: TCP (6)
- RST ratio near 1.0
- High packet count
- No SYN or ACK packets (no legitimate handshake)

**MITRE ATT&CK:** T1498 — Network Denial of Service

## ICMP Flood (Ping Flood)

ICMP echo request floods saturate the target's network link or exhaust CPU on hosts
processing echo replies.  Often used as a simple volumetric attack.

**Flow indicators:**
- Protocol: ICMP (1)
- High packet count with very low mean IAT
- Consistent payload size (standard ping is 56 bytes)

**MITRE ATT&CK:** T1498.001 — Direct Network Flood

## UDP Flood

UDP floods send high volumes of UDP datagrams to random or targeted ports, forcing
the target to process and respond with ICMP Destination Unreachable messages.

**Flow indicators:**
- Protocol: UDP (17)
- Very high packet count
- High byte count relative to duration
- Random or non-standard destination ports

**MITRE ATT&CK:** T1498.001 — Direct Network Flood

## DNS Amplification

DNS amplification uses open DNS resolvers to reflect and amplify traffic toward a
victim.  The attacker sends small queries with the victim's spoofed source IP; the
resolver sends large responses to the victim.

**Flow indicators:**
- Protocol: UDP (17)
- Source or destination port 53 (DNS)
- Large mean payload size (>512 bytes — amplified responses)
- High packet count
- Asymmetric byte ratio (many more bytes received than sent)

**MITRE ATT&CK:** T1498.002 — Reflection Amplification

## Slowloris

Slowloris opens many connections to a target web server and keeps them alive by
sending partial HTTP headers at regular intervals, exhausting the server's
connection pool without requiring high bandwidth.

**Flow indicators:**
- Protocol: TCP (6) targeting port 80 or 443
- Very long flow duration with very few packets (slow drip)
- Small payload sizes
- No FIN or RST within the flow — connection never completes
