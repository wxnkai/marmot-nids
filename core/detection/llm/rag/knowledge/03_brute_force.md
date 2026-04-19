# Brute Force Attack Patterns

## Overview

Brute force attacks attempt to gain unauthorised access by systematically trying
passwords, keys, or credentials against authentication endpoints.  They are
characterised by high connection rates to specific service ports.

## SSH Brute Force

Automated tools (Hydra, Medusa, Ncrack) send rapid login attempts to SSH
services on port 22.

**Flow indicators:**
- Protocol: TCP (6)
- Destination port 22 (SSH)
- High packet count in a short duration window
- Multiple small exchanges (login prompt + attempt + failure)
- Duration typically under 60 seconds for automated tools
- Medium payload sizes (SSH banner + auth packets)

**MITRE ATT&CK:** T1110.001 — Password Guessing

## HTTP/HTTPS Brute Force

Credential stuffing or form-based brute force against web login pages.
Can target port 80 (HTTP) or 443 (HTTPS).

**Flow indicators:**
- Protocol: TCP (6)
- Destination port 80 or 443
- High packet count relative to duration
- Consistent payload sizes (repeated POST requests with same structure)
- Duration typically under 120 seconds for automated tools

**MITRE ATT&CK:** T1110.001

## RDP Brute Force

Automated password guessing against Windows Remote Desktop Protocol on
port 3389.

**Flow indicators:**
- Protocol: TCP (6)
- Destination port 3389
- High packet count in a short window
- Multiple short-lived connections or rapid connection resets

**MITRE ATT&CK:** T1110.001

## FTP Brute Force

Login attempts against FTP services on port 21.  FTP transmits credentials
in cleartext, making brute force both an access and disclosure risk.

**Flow indicators:**
- Protocol: TCP (6)
- Destination port 21
- High packet count, short duration
- Small payload sizes (username/password exchange)

**MITRE ATT&CK:** T1110.001

## Telnet Brute Force / Access

Telnet on port 23 transmits all data (including credentials) in cleartext.
Any Telnet session on a production network is a security concern regardless
of whether it is a brute force attempt.

**Flow indicators:**
- Protocol: TCP (6)
- Destination port 23
- Any connection with more than a few packets

**MITRE ATT&CK:** T1021 — Remote Services

## Detection Considerations

- Brute force flows often have min_port matching the service port (22, 80, 443, 3389, 21)
- Duration thresholds help distinguish brute force from legitimate sessions
- Credential rotation attacks (password spraying) may use fewer attempts per account,
  requiring correlation across flows to different service instances
