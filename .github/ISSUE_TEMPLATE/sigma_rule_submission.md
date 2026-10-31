---
name: Sigma Rule Submission
about: Submit a new or updated SigmaHQ detection rule for the community
title: '[RULE] <Attack Pattern or Technique>'
labels: ['sigma-rule', 'community']
assignees: ''
---

**Rule Title:**
[e.g. Web SQL Injection Exploitation Technique]

**MITRE ATT&CK Mapping:**
- Tactic: [e.g. Initial Access]
- Technique: [e.g. T1190]

**Target Log Source:**
- Category: [e.g. webserver, process_creation]
- Product: [e.g. windows, linux, tumlog]

**Rule Severity:**
[ ] Low  [ ] Medium  [ ] High  [ ] Critical

**Rule YAML Definition:**
```yaml
title: ...
id: ...
status: test
description: ...
level: high
tags:
    - attack.execution
detection:
    selection:
        PayloadSanitized|contains:
            - '...'
    condition: selection
falsepositives:
    - ...
```

**Testing & Verification Evidence:**
Paste log sample or test output showing rule triggers properly and does not produce false positives on normal traffic.
