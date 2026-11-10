# AGENTS.md — TUM-OpenSIEM Agent Operating Mandate
**Authority:** Office of the CTA & Resident Technical Auditor for Log Mesh & WORM Storage (RTA-03)  
**Baseline Standard:** [EI-VS v2.0.0 (TUM-STD-ENG-001)](file:///D:/TUM/tum-socs/GEMINI.md)  
**Status:** STRICT ENFORCEMENT  

---

## 1. Agent Attitude & Operational Calibration

Every AI coding agent operating within `tum-socs` must strictly adhere to the following principles:

1. **Benchmark Integrity:**
   - Do NOT quote in-memory burst micro-benchmarks (such as 8.8M EPS over 11ms) as verified continuous production throughput.
   - Any throughput or latency assertion must specify whether persistent disk storage write-flush was enabled or bypassed.
   - Numerical performance claims must specify the hardware testbed, sample size, and variance calculation.

2. **Compliance & Storage Semantics:**
   - Thai CCA Sec 26 compliance requires durable, append-only WORM ledger storage with SHA-256 Merkle chaining.
   - Do NOT store statutory audit logs solely in volatile RAM collections.

3. **Zero-Persona & Direct Communication:**
   - Do not use performative filler or sycophancy. Output direct technical data, metrics, and actionable architectural trade-offs.

4. **Verification Gate:**
   - Before completing tasks, run:
     ```powershell
     dotnet build
     dotnet test --configuration Release
     ```
