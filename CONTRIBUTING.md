# Contributing to TUM-OpenSIEM

Thank you for your interest in contributing to **TUM-OpenSIEM**!  
TUM-OpenSIEM is a high-performance, open-source SIEM engine designed to eliminate the "Ingestion Tax" and empower SecOps teams with zero-friction threat detection, Native .NET 8 AOT throughput, and cryptographically verified WORM custody.

---

## Code of Conduct

All contributors and community members are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). Please report unacceptable behavior to `security@tum.trust` or project maintainers.

---

## How Can You Contribute?

1. **SigmaHQ Detection Rules (`rules/`):** Submit new detection rules for emerging threats, CVEs, or attack techniques.
2. **Columnar Storage & Log Parsers (`Tum.Log/`):** Optimize ClickHouse/DuckDB batch adapters, create new firewall or cloud parser plugins.
3. **Core Engine Performance:** Enhance zero-allocation RingBuffer pipelines, eBPF sniffer throughput, or AOT serialization.
4. **Web Console & Visualizers (`visualizers/`):** Improve the interactive threat explorer, WebGL attack map, or executive compliance reporting.
5. **Documentation & Benchmarks:** Expand RFCs, test vectors, deployment recipes, or language localizations.

---

## Contributing Sigma Detection Rules

Community Sigma rules reside under the `rules/` directory categorized by attack stage:

- `rules/web/`: Web application attacks (SQLi, XSS, Path Traversal, SSRF)
- `rules/execution/`: Command execution, PowerShell cradles, reverse shells
- `rules/credential_access/`: Mimikatz, LSASS dumping, credential harvesting
- `rules/identity/`: Brute-force authentication, MFA fatigue, privilege abuse
- `rules/ransomware/`: Canary tripwire tampering, bulk encryption indicators
- `rules/exfiltration/`: Data staging, outbound leaks, DNS tunneling

### Sigma Rule YAML Specification
```yaml
title: Detects Specific Attack Pattern
id: 12345678-1234-1234-1234-123456789abc
status: stable
description: Detailed description of the threat vector and attacker intent
level: high # low | medium | high | critical
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventName: 'PROCESS.CREATE'
        PayloadSanitized|contains:
            - 'malicious_argument_1'
            - 'malicious_argument_2'
    filter:
        UserId: 'authorized_service_account'
    condition: selection and not filter
falsepositives:
    - Legitimate administrative tooling
```

---

## Development Setup

### Prerequisites
- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- [Docker](https://www.docker.com/) & Docker Compose (optional for ClickHouse integration)
- Git

### Build and Run Tests
```bash
# Clone the repository
git clone https://github.com/PasitTum/tum-socs.git
cd tum-socs

# Restore and build the solution
dotnet build

# Run unit tests and high-throughput benchmarks
dotnet test

# Run code style formatting check
dotnet format --verify-no-changes
```

### Running the Live SIEM Server
```bash
# Launch ClickHouse columnar backend
docker compose up -d clickhouse

# Run the OpenSIEM Server & Web Console
dotnet run --project Tum.Siem.Server
```
Open your browser at `http://localhost:5000` to access the interactive Executive HUD & Threat Explorer.

---

## Git Flow & Pull Request Workflow

We strictly follow the **Git Flow** branching model documented in [GIT_FLOW.md](GIT_FLOW.md):

1. **Base Branch:** Always branch off `develop`.
2. **Branch Naming:** `feature/<ticket-key>-<short-description>` (e.g. `feature/SCRUM-42-add-cve-rules`).
3. **Conventional Commits:**
   - `feat(...)`: New feature or detection capability
   - `fix(...)`: Bug fix
   - `docs(...)`: Documentation updates
   - `perf(...)`: Performance optimization
   - `test(...)`: Unit/integration tests
4. **Verification Loop:** All 50+ automated unit tests and `dotnet format` must pass before submitting a Pull Request.
5. **Issue Reference:** Every PR must reference its corresponding Jira/GitHub Issue (e.g. `[SCRUM-6] (#2)`).

Thank you for securing sovereign cyber ecosystems with TUM-OpenSIEM!
