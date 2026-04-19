# Web Application Attacks

## Overview

Web application attacks target HTTP/HTTPS services to exploit vulnerabilities
in application logic, input handling, or server configuration.  These attacks
are primarily detected through payload analysis, but flow-level indicators
can provide supporting evidence.

## SQL Injection (SQLi)

An attacker injects SQL syntax into application input fields (forms, URL
parameters, cookies) to manipulate the database backend.

**Flow indicators:**
- Protocol: TCP (6) on port 80 or 443
- Payload sizes may be larger than normal (injected SQL strings)
- Multiple rapid requests to the same endpoint
- Response sizes may vary significantly (data exfiltration vs. error pages)

**MITRE ATT&CK:** T1190 — Exploit Public-Facing Application

## Cross-Site Scripting (XSS)

XSS attacks inject JavaScript or HTML into web pages viewed by other users.
Reflected XSS sends the payload in a request parameter; stored XSS persists
in the application database.

**Flow indicators:**
- Protocol: TCP (6) on port 80 or 443
- Request payloads may contain JavaScript syntax
- Multiple probe requests from the same source in rapid succession

**MITRE ATT&CK:** T1059.007 — Command and Scripting Interpreter: JavaScript

## Directory Traversal

Attempts to access files outside the web root using path traversal sequences
(``../``) in URL paths or parameters.

**Flow indicators:**
- Protocol: TCP (6) on port 80 or 443
- Requests with ``../`` patterns in URLs
- Targeting configuration files (``/etc/passwd``, ``web.config``)
- Multiple requests to different paths from the same source

**MITRE ATT&CK:** T1083 — File and Directory Discovery

## Command Injection

An attacker injects operating system commands through vulnerable application
input fields.  Commands are executed with the web server's privileges.

**Flow indicators:**
- Protocol: TCP (6) on port 80 or 443
- Payloads containing shell metacharacters (`;`, `|`, `` ` ``, `$()`)
- Unusual response sizes or timing (command execution latency)

**MITRE ATT&CK:** T1059 — Command and Scripting Interpreter

## Detection Considerations

Web application attacks are primarily payload-based and are harder to detect
from flow statistics alone.  The LLM should consider:

- Volume of requests to a single service in a short window
- Unusual request-to-response size ratios
- Sequential probing patterns (many requests, each slightly different)
- Combination of web port targeting with brute-force-like packet counts
