# TUM Group Engineering Integrity & Verification Standard (EI-VS)

**Document Code:** TUM-STD-ENG-001  
**Version:** 2.0.0  
**Effective Date:** 10 November 2026  
**Document Owner:** Office of the Chief Technical Auditor (CTA) & Engineering Working Group  
**Approved By:** Chairman of the Board & Chief Technical Auditor (CTA)  
**Review Cadence:** Semi-Annual (Every 6 months) or upon major architectural restructuring  
**Scope:** Universal engineering standard for all software repositories, services, human engineers, and autonomous AI agents within the organization  
**Precedence:** Repository-level baseline engineering standard; subordinate to applicable statutory regulations, corporate security policies, and authorized executive directives  
**Codification Notice:** This standard (EI-VS) is codified directly as the repository engineering instructions (`GEMINI.md` or equivalent agent configuration files). References to "this Standard", "EI-VS", or "the repository engineering standard" refer interchangeably to this codified baseline.

---

### REVISION HISTORY

| Version | Effective Date | Approver | Summary of Changes |
| :--- | :--- | :--- | :--- |
| **1.0.0** | 15 Oct 2026 | Chairman & CTA | Initial baseline: 7-Rule Ironclad Constitution establishing fundamental prohibitions on deceptive mocks and fabricated telemetries. |
| **2.0.0** | 10 Nov 2026 | Chairman & CTA | Enterprise evolution: Standardized as EI-VS. Introduced proportional risk tiers, context-aware resilience, rigorous benchmark reproducibility standards, formal Delegation of Authority (DoA) with mandatory security escalation, mock lifecycle tracking, and precise cryptographic attribution criteria. |

---

### SECTION 1: CORE GOVERNANCE & ENGINEERING PRINCIPLES

#### 1. Truth in Representation, Transparent Labeling & Mock Lifecycle
* **Core Principle:** Systems, interfaces, and technical documentation must accurately reflect the true operational state and capabilities of the software.
* **Requirements:**
  * **Transparent Labeling:** Mocks, synthetic data generators, test stubs, and simulated peripherals are valid engineering instruments for unit testing, offline development, and preliminary UX evaluation. They must be explicitly labeled (e.g., `[MOCK]`, `[SYNTHETIC]`, `[OFFLINE_PREVIEW]`) in user interfaces, logging streams, and API payload contracts.
  * **Prohibition of Deceptive Attribution:** Synthetic datasets, pseudo-random generators (`Math.random()`), or hardcoded data buffers must never be attributed as live production telemetry, authentic kernel/network events, or physical sensor readings.
  * **Mock Lifecycle Management:**
    * *Trigger & Ownership:* Every mock or test stub introduced into the codebase must record:
      1. Origin Timestamp (Commit date / Issue creation date).
      2. Assigned Accountable Owner (Designated Engineer / Tech Lead).
      3. Explicit Expiration Date / TTL (Time-To-Live, default maximum: 30 calendar days).
    * *Expiration Enforcement:* Upon reaching the TTL expiration date, one of the following actions must occur:
      1. The mock is removed and replaced with integrated production logic.
      2. A written extension is granted by a Level 2 Authority with documented rationale and an updated retirement date.
      3. If neither occurs, deployment pipelines must fail-closed (`BLOCK_DEPLOYMENT`) preventing release to staging or production.
  * **Real Production-Readiness Evaluation:**
    * Components, API endpoints, or user flows that depend on unintegrated mocks, stubs, or synthetic drivers are strictly classified as **0% Functionally Ready (Unimplemented / In-Progress)**.
    * When computing overall system readiness across a multi-component deliverable:
      $$\text{Readiness Metric (\%)} = \left( \frac{\sum_{i=1}^{N} C_i \times W_i}{\sum_{i=1}^{N} W_i} \right) \times 100$$
      Where $W_i$ is the architectural weight of component $i$, and $C_i \in [0.0, 1.0]$ represents verified functional readiness. Any component utilizing mocks, stubs, or unintegrated simulations receives $C_i = 0.0$ regardless of UI completion.

#### 2. Context-Aware Resilience & Failure Behavior
* **Core Principle:** Failure handling must be determined by the component's threat model, data sensitivity, and operational criticality.
* **Requirements:**
  * **Security Boundaries (Fail-Closed):** Authentication services, cryptographic signature verification, authorization decision points, statutory ledger mutations, and hardware-backed biometric capture must fail closed upon dependency or hardware loss, returning explicit operational errors (e.g., HTTP 503, `HARDWARE_UNAVAILABLE`, `SIGNATURE_VERIFICATION_FAILED`).
  * **Operational Services (Graceful Degradation):** Non-critical operational pathways (e.g., read-only dashboards, metric aggregation, cached catalog lookups) may enter degraded or cached read-only states when secondary dependencies are unavailable, provided the degraded status is visibly surfaced in telemetry headers and UI badges.
  * **Prohibition of Silent Masking:** Systems must never silently catch and suppress infrastructure or security failures by substituting synthetic success payloads.

#### 3. Cryptographic Provenance & Technical Precision
* **Core Principle:** Cryptographic capabilities and security postures must be technically sound, rigorously implemented, and precisely described.
* **Requirements:**
  * **Established Cryptographic Engines:** Security-critical cryptographic operations must utilize audited, established implementations (e.g., operating system CNG/CryptoAPI, BouncyCastle, OpenSSL, or recognized bindings such as `liboqs`) matching the designated risk tier.
  * **Precision in Cryptographic Claims:** Technical documentation, code comments, and product claims must adhere to strictly differentiated terminology:
    1. *Reference Test-Vector Conformance:* Implementation has been validated against published standard reference test vectors (e.g., NIST CAVP vectors, ICAO PKD test suites). Does not imply government lab validation.
    2. *Audited / Established Engine:* Component utilizes a recognized, publicly audited open-source or commercial cryptographic library.
    3. *Formally Certified / Validated:* Reserved exclusively for products that have obtained official third-party laboratory certification (e.g., active NIST CMVP / FIPS 140-3 validation number, Common Criteria EAL certificate).
    4. *Formal Mathematical Verification:* Reserved exclusively for cryptographic code proven using formal proof assistants (e.g., Coq, F*, Isabelle/HOL) or verified compilers.
  * **Prohibition of Algorithmic Simulations:** Proprietary cryptographic approximations, wrapping classical hashes in XOR loops, or padding hashes to mimic post-quantum key sizes must never be described or represented as quantum-safe, military-grade, or standards-compliant.

#### 4. Semantics-Driven Persistence
* **Core Principle:** Data storage mechanisms must match the durability, auditability, and consistency guarantees required by the business domain.
* **Requirements:**
  * **Core Enterprise Entities:** Invoices, financial ledger vouchers, immutable audit trails, legal identity records, and access revocation lists require durable storage (e.g., ACID-compliant relational databases, distributed consensus stores, or append-only ledgers) with version-controlled schema migrations.
  * **Ephemeral Data:** Transient caches, temporary UI session states, and high-frequency metric buffers may use in-memory storage, provided eviction, sizing, and lifecycle policies are defined.
  * **Session Token Storage Constraints:** Session tokens and authentication states may utilize in-memory or distributed cache storage (e.g., Redis) only when the component threat model explicitly evaluates and formally accepts the operational risks of sudden session loss (e.g., cold restarts) and eventual consistency in token revocation. Security-critical credentials requiring immediate global revocation must be backed by consistent, durable registries.

#### 5. Proportional Verification & Reproducible Benchmarks
* **Core Principle:** Verification rigor must correspond to component criticality, failure risk, and published performance claims.
* **Requirements:**
  * **Risk Tiers:**
    * *Tier 1 (Critical Security, Cryptography, Financial Ledger, Identity):* Requires unit, integration, and negative/adversarial testing. Mutation analysis is required for claim-critical logic paths.
    * *Tier 2 (Standard Business Logic, Application APIs):* Requires automated test suites verifying primary workflows, edge cases, input validation, and schema contracts.
    * *Tier 3 (Internal Utilities, Prototypes):* Basic smoke tests and static type checking.
  * **Reproducible Benchmarks:** Any published numerical performance claim (e.g., "50,000 EPS", "sub-millisecond latency") must be backed by a verifiable benchmark package containing:
    1. An executable benchmark runner script stored in test assets.
    2. Context-relevant environment documentation:
       * *Computational / Cryptographic Benchmarks:* CPU model/architecture, core count, RAM specification, compiler/runtime version, and execution optimization flags.
       * *Network-Bound Benchmarks:* NIC throughput, network topology, concurrency levels, and connection pooling parameters. (Record `N/A: Domain Independent` for non-network tasks).
       * *Storage / Ledger Benchmarks:* Disk medium (NVMe/SSD/HDD), IOPS capacity, filesystem type, and write-flush semantics. (Record `N/A: Domain Independent` for non-storage tasks).
    3. Transparent statistical methodology: Documented warm-up period, sample duration, distribution metrics (p50, p90, p99 percentiles for latency), and sample variance or 95% confidence intervals with explicit calculation formulas.
  * **Benchmark Artifact Storage:** High-volume raw metric streams and packet captures must not be committed directly into Git repositories. They must be uploaded to secure, access-controlled artifact storage, with immutable cryptographic SHA-256 digests, run timestamps (ISO 8601), and traceable reference links recorded in the repository.

#### 6. Calibrated Communication & Zero-Persona Protocol
* **Core Principle:** Agent and engineer communication must be objective, factual, concise, and focused on verifiable reality.
* **Requirements:**
  * **Calibrated Handling of Incomplete Information:** When physical inputs, sensor data, or empirical evidence are insufficient to substantiate a factual assertion:
    1. Disclose confirmed facts (Knowns).
    2. Disclose unverified parameters, missing dependencies, or test limitations (Unknowns/Assumptions).
    3. State the level of confidence or define the specific inputs needed to reach certainty.
    *(Mandatory Epistemic Abstention is enforced when guessing or speculating creates security, legal, or operational risks).*
  * **Zero-Persona Standard:**
    * Strict ban on meta-sycophancy, metaphorical compliments, and performative declarations of virtue or neutrality (e.g., self-congratulatory preambles about being unbiased, lecturing on ethics, or emotional padding).
    * Communication proceeds directly to the factual core, technical trade-offs, and actionable decisions.

#### 7. Layered Governance, Delegation of Authority (DoA) & Break-Glass SLAs
* **Core Principle:** Automated gates enforce standards continuously, while explicit human authority governs exceptions and technical debt.
* **Delegation of Authority (DoA) Levels:**
  * **Level 1 (Constitutional & Standard Revisions):** Chairman of the Board or Chief Technical Auditor (CTA).
  * **Level 2 (Architectural Invariants & Security Exceptions):** VP of Engineering or Shared Security Guild Lead.
  * **Level 3 (Operational CI Bypass & Local Hotfix):** Designated Technical Lead or Solutions Architect of the respective Business Unit.
* **Mandatory Security Escalation Rule:**
  * Any exception, patch, or emergency hotfix that touches a **Security Boundary, Cryptographic Implementation, Identity Registry, or Financial Ledger** is strictly disqualified from Level 3 approval and **MUST escalate to Level 2 Authority**, regardless of operational urgency.
* **Designated Backup / Delegate Authority:**
  * When a designated Level 2 approver is unreachable during an operational emergency, approval authority falls to the **Designated Secondary Lead** (as defined in the corporate operating model) or escalates directly to **Level 1 (CTA / Chairman)**. Unilateral self-approval by the implementer is strictly prohibited.
* **Break-Glass Protocol & Debt Retirement SLA:**
  * When automated guardrails block an urgent deployment, an authorized authority may invoke a Break-Glass bypass.
  * *Mandatory Documentation:* Every bypass must record:
    1. Operational justification.
    2. Approving authority (Name, Role, and DoA Level).
    3. Tracked Issue Ticket for technical debt resolution.
  * *Retirement SLA:* All Break-Glass exceptions carry a mandatory **14-calendar-day resolution SLA** (or within the active sprint). The CTA audits all open exceptions bi-weekly. Unresolved exceptions exceeding the SLA are escalated as critical governance non-conformances.

#### 8. Role-Aware Task Integrity & Amendment Governance
* **Core Principle:** Engineering constraints must be respected during task execution and cannot be bypassed autonomously.
* **Requirements:**
  * **Prohibition of Autonomous Standard Modification:** Autonomous coding agents must never modify, weaken, or delete repository governance rules (`GEMINI.md` / EI-VS) to unblock a failing task or claim completion. Blockers must be reported factually.
  * **Proposal Mechanisms vs. Approval Authority:**
    * Pull Requests (PR), Requests for Comments (RFC), and `/learn` review workflows are **Proposal Mechanisms (ช่องทางการเสนอแก้ไข)** available to all engineers and agents.
    * **Approval Authority** for any substantive modification to this Standard is strictly reserved for **Level 1 Authority (Chairman of the Board or CTA)**. No proposal becomes effective without explicit Level 1 ratification.
  * **Subordination to Documented Authority:** When an authorized user (acting within their DoA level) explicitly directs an action that relaxes a standard for a bounded scope (e.g., temporary test mock for UI layout), the agent must implement it strictly within that bounded scope, apply required labels, and record the authorizing ticket.

---

### SECTION 2: OPERATIONAL DECISION MATRIX

| Domain | Recommended Practice (DO) | Prohibited Practice (DON'T) |
| :--- | :--- | :--- |
| **1. Representation** | Label prototype UI with `[DEMO MODE]`, set 30-day TTL, and assign issue ticket to Tech Lead. | Present `Math.random()` feeds as genuine kernel security telemetry on an executive dashboard. |
| **2. Resilience** | Return HTTP 503 upon smart card reader disconnection; serve cached catalog during secondary DB slowdown. | Silently generate synthetic citizen identity data when hardware fails to make a demo appear functional. |
| **3. Cryptography** | State "Passes NIST SP 800-208 test vectors using liboqs v0.10"; cite official test vectors. | XOR an HMAC output and document it as "Formally Certified ML-DSA Post-Quantum Cryptography". |
| **4. Persistence** | Store ledger vouchers in PostgreSQL; store temporary session tokens in Redis with evaluated loss risk. | Store enterprise master records exclusively in volatile in-memory collections (`Map<string, any>`). |
| **5. Benchmarks** | Provide reproducible test script, relevant hardware specs (or N/A), 95% CI, and SHA-256 digest of logs. | Claim "50,000 EPS Military Grade" in marketing materials without reproducible test scripts or raw metrics. |
| **6. Communication** | State "Hardware sensor unavailable in this runtime; unable to confirm biometric match." | "As your dedicated CTA, I must decline to answer because I am thoroughly unbiased..." |
| **7. Break-Glass** | Record bypass: `[BREAK-GLASS: Level 2 Approved by VP Eng, Security Boundary Patch, Ticket #1042, Due: 2026-11-24]`. | Use Level 3 hotfix bypass to alter authentication token verification logic without Level 2 approval. |
| **8. Governance** | Propose rule refinement via RFC Pull Request and await Level 1 ratification. | Autonomous agent edits `GEMINI.md` to remove a linter rule so that its build passes. |

---

### SECTION 3: SUBSIDIARY OPERATIONAL APPENDIX — TUM-OPENSIEM (TUM SOCS)

* **Business Unit:** TUMLog / TUM-OpenSIEM Business Unit (Distributed Systems & Log Mesh BU)
* **Risk Tier Classification:** **Tier 1 (Immutable WORM Audit Ledger, CCA Sec 26 Compliance, Real-time Ingestion Engine)**
* **Core Technology Stack:** C# / .NET 8 Native AOT, ClickHouse MergeTree, DuckDB, Syslog RFC 5424 / 3164
* **Mandatory Verification Commands:**
  ```powershell
  dotnet build
  dotnet test --configuration Release
  ```
* **Specific Invariant Checkpoints:**
  1. *WORM Ledger Durability:* Security audit logs claiming compliance with Thai Computer Crime Act Sec 26 must write to append-only storage with SHA-256 Merkle chain verification. Pure in-memory circular buffers without persistent write-flush semantics are prohibited for compliance ledgers.
  2. *High-Throughput Benchmark Evidence:* Numerical claims (e.g., "737k EPS/core", "8.8M EPS") must supply reproducible load generators, recording CPU model, thread count, RAM, and 95% confidence intervals.
  3. *PII Sanitization:* Thai Citizen ID and PAN data must be masked at ingestion boundary before persistence.
