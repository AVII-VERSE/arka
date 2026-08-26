# E2E Test Infra: ARKA Enterprise SIEM & XDR Platform

## Test Philosophy
- Opaque-box, requirement-driven. No dependency on implementation internals.
- Zero fake data verification: All endpoints and services must reject/handle empty states and provide genuine responses.
- Methodology: Category-Partition + Boundary Value Analysis + Pairwise Combinatorial + Real-World Workload Testing.

## Feature Inventory & Test Matrix
| # | Feature | Source | Tier 1 (Coverage) | Tier 2 (Boundary) | Tier 3 (Pairwise) | Tier 4 (Real-World) |
|---|---------|--------|:-----------------:|:-----------------:|:-----------------:|:-------------------:|
| 1 | R1: Rootcheck Filesystem & Rootkit Scanner | ORIGINAL_REQUEST §1 | 5 | 5 | ✓ | ✓ |
| 2 | R1: Rootcheck Hidden Process & Sockets | ORIGINAL_REQUEST §1 | 5 | 5 | ✓ | ✓ |
| 3 | R2: SCA Multi-Platform CIS Evaluator | ORIGINAL_REQUEST §2 | 5 | 5 | ✓ | ✓ |
| 4 | R2: SCA Compliance Scoring & Persistence | ORIGINAL_REQUEST §2 | 5 | 5 | ✓ | ✓ |
| 5 | R3: Syscollector Hardware, OS & Processes | ORIGINAL_REQUEST §3 | 5 | 5 | ✓ | ✓ |
| 6 | R3: Syscollector Packages, Ports, REST APIs | ORIGINAL_REQUEST §3 | 5 | 5 | ✓ | ✓ |
| 7 | R4: Active Response IP Block & Process Kill | ORIGINAL_REQUEST §4 | 5 | 5 | ✓ | ✓ |
| 8 | R4: Active Response Quarantine & Backend | ORIGINAL_REQUEST §4 | 5 | 5 | ✓ | ✓ |
| 9 | R5: Vulnerability CVE Semantic Version Matching | ORIGINAL_REQUEST §5 | 5 | 5 | ✓ | ✓ |
| 10 | R5: Vulnerability Severity & Finding Lifecycle | ORIGINAL_REQUEST §5 | 5 | 5 | ✓ | ✓ |

## Test Runner
- Command: `python -m pytest backend/tests agent/tests -v`
- Quality Linters:
  - `ruff check backend agent`
  - `mypy backend app agent/arka_agent`
  - `bandit -r backend/app agent/arka_agent -ll`

## Real-World Application Scenarios (Tier 4)
| # | Scenario | Features Exercised | Complexity |
|---|----------|--------------------|------------|
| 1 | Log4Shell RCE Exploitation & Automated Containment (CVE-2021-44228) | Vulnerability Engine, Active Response (IP block + process kill), FIM | High |
| 2 | Kernel Rootkit Persistence & Backdoor C2 Socket | Rootcheck (artifact + socket scan), Alert generation, Quarantine | High |
| 3 | CIS Benchmark Drift & Baron Samedit Privilege Escalation (CVE-2021-3156) | SCA CIS Engine, Vulnerability Engine, Security Incident creation | Medium |
| 4 | High-Volume Endpoint Brute Force Attack | Event Ingestion, Detection Rule `BRUTE_FORCE_LOGIN`, Active Response IP block | High |
| 5 | Agent Offline Buffering & Resilient Re-synchronization | SQLiteQueue FIFO buffer, HTTP transport, multi-collector batch ingest | Medium |
