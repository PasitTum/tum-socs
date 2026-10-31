# Security Policy

## Supported Versions

TUM-OpenSIEM actively maintains security updates and patches for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | :white_check_mark: |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

---

## Reporting a Vulnerability

The TUM-OpenSIEM project takes the security of our open-source codebase, cryptographic ledgers, and telemetry collectors extremely seriously.

If you believe you have discovered a security vulnerability in TUM-OpenSIEM, please **DO NOT** disclose it publicly via GitHub Issues, Discussions, or social media.

Instead, please report it privately:

- **Email:** `security@tum.trust` or `daywakler01@gmail.com`
- **Subject:** `[Vulnerability Report] TUM-OpenSIEM: <Brief Summary>`

### What to Include in Your Report
1. Description of the vulnerability and its potential impact.
2. Steps to reproduce the vulnerability (proof-of-concept script, curl commands, or sample payload).
3. Component affected (e.g. `TumRingBufferIngestor`, `TamperProofLogChain`, `ClickHouseSinkAdapter`, `SigmaRuleEngine`).
4. Any proposed remediations or patches.

### Our Response SLA
- **Initial Response:** Within 24 hours.
- **Triage & Severity Assessment:** Within 72 hours.
- **Remediation & Patch Release:** Coordinated with reporter, typically within 7–14 days.

We sincerely appreciate responsible disclosure and will credit researchers in our release notes and Hall of Fame!
