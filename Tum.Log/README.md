# TUMLog — Sovereign Application Compliance & Threat Defense Mesh
### Powered by TUM &bull; TUM Trust Security

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![.NET 5.0 | 8.0 | 10.0](https://img.shields.io/badge/.NET-5.0%20%7C%208.0%20%7C%2010.0-blueviolet.svg)](https://dotnet.microsoft.com/)
[![Compliance](https://img.shields.io/badge/Compliance-Thai%20CCA%20Sec%2026%20%7C%20PDPA%20%7C%20ISO%2027001-emerald.svg)](#)

TUMLog is an enterprise-grade sovereign application-layer logging, compliance audit, and real-time threat defense mesh engineered for modern web applications, microservices, and financial systems.

## Key Capabilities

- **Thai Computer Crime Act B.E. 2560 Section 26 Compliance:** Mandatory 90-day WORM immutable storage, Stratum 1 NTP reference time-stamping (`time.navy.mi.th`), and SHA-256 Merkle chain linking.
- **ISO/IEC 27001:2022 (Annex A.12.4):** Standardized event action taxonomy (`AUTH.LOGIN`, `DATA.READ`, `DATA.EXPORT`, `SEC.PRIVILEGE_CHANGE`).
- **AI-Powered PII Sanitizer:** Modulo-11 Thai National ID verification & masking (`1-XXXX-XXXXX-XX-1`), Luhn PAN card masking (`4111-XXXX-XXXX-1111`), JWT token and secret token sanitization.
- **Bidirectional Scanning:** Inbound OWASP Top 10 threat detection (SQLi, XSS, Path Traversal) + Outbound leak shield (database syntax errors, stack trace dumps, private key blocks).
- **Automated Endpoint Discovery & PII Data Flow Matrix:** Visual catalog of all active routes, mapping sensitive data movement.
- **Four-Tier Ingestion Strategy:**
  1. *Tier 1: Zero-Touch Middleware (`app.UseTumLog()`)*
  2. *Tier 2: Declarative AOP Attribute (`[TumAudit]`)*
  3. *Tier 3: Fluent Programmatic API (`TumLog.Capture()`)*
  4. *Tier 4: Lock-Free Async Ring Buffer Channel (< 0.15ms latency impact)*
- **Pluggable Multi-Destination Sinks:** Local WORM, Syslog RFC 5424 over TLS, Elasticsearch/OpenSearch, and AWS S3 Object Lock.

## Installation & Quickstart

```bash
dotnet add package Tum.Log
```

In `Program.cs`:
```csharp
// 1. Register TUMLog services
builder.Services.AddTumLog(options =>
{
    options.ApplicationName = "EnterpriseApp";
    options.WormRetentionDays = 90;
    options.DefenseMode = ThreatDefenseMode.AuditOnly;
});

// 2. Add to HTTP Middleware Pipeline (Zero code changes required!)
app.UseTumLog();
```
