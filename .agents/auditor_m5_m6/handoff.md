# Forensic Audit Report: Milestones M5 & M6

**Work Product**: Milestones M5 (Active Response Container & Service) & M6 (Vulnerability Detection & CVE Correlation Engine)  
**Auditor**: Teamwork Preview Auditor #3 (`auditor_m5_m6`)  
**Profile**: General Project (Integrity Forensics)  
**Verdict**: **CLEAN**  

---

### Phase Results Summary

| Check Name | Status | Details |
|---|:---:|---|
| **Phase 1: Source Code & Integrity Inspection** | **PASS** | Zero hardcoded test outputs, zero facade implementations, zero mock/fake fallback dictionaries. |
| **Phase 1: Active Response Containment Logic** | **PASS** | Genuine two-phase process termination, OS-native firewall blocking (`netsh`/`iptables`), secure file quarantine vault with SHA-256 manifest & restore integrity checks. |
| **Phase 1: Containment Safety Guardrails** | **PASS** | Strict allowlists for loopback/broadcast/backend IPs, system PIDs (0, 1, 2, 4, agent PID, parent PID, critical OS process names), and critical OS binaries. |
| **Phase 2: Vulnerability Correlation & Semantic Versioning** | **PASS** | Genuine PEP 440 semantic version range matching (`packaging.version`), letter suffix & patch level normalization (`1.1.1t`, `1.9.5p2`), OR-branched specs (`||`), FIRST.org CVSS v3.1 base score computation. |
| **Phase 2: Database Persistence & Lifecycle** | **PASS** | Full relational mapping and persistence for `ActiveResponseTask`, `AuditLog`, `CVEItem`, `VulnerabilityFinding`, and `VulnerabilityScanReport`. Automated alert dispatch for High/Critical vulnerabilities and alerts. |
| **Phase 2: Zero Fake Data Compliance** | **PASS** | Querying endpoints on empty databases returns empty lists (`[]`), never fake/mock pre-populated records or hardcoded agent reports. |

---

## 1. Observations

### 1.1 Active Response Agent & Service (Milestone M5)
- **Host Firewall Containment & Rollback (`agent/arka_agent/active_response.py:167-360`)**:
  - `block_ip()` generates platform-native firewall commands: `netsh advfirewall firewall add rule name=ARKA_Block_<ip> dir=in action=block remoteip=<ip>` on Windows; `iptables -I INPUT -s <ip> -j DROP -m comment --comment ARKA_ActiveResponse` on Linux (lines 199–226).
  - Automated rollback timers (`threading.Timer`) are scheduled upon execution if `duration_seconds` is provided, automatically invoking `unblock_ip()` (lines 253–263).
- **Two-Phase Safe Process Termination (`agent/arka_agent/active_response.py:361-492`)**:
  - `_execute_two_phase_kill()` executes Phase 1 graceful `proc.terminate()` + `child.terminate()` with a 3.0s wait window (`psutil.wait_procs`), escalating to Phase 2 `proc.kill()` force termination only if processes remain alive (lines 361–395).
- **Secure File Quarantine Vault & Cryptographic Verification (`agent/arka_agent/active_response.py:505-720`)**:
  - `quarantine_file()` validates existence, checks critical OS binaries against `PROTECTED_FILE_PATTERNS`, streams SHA-256 hash calculation (chunk size 64KB), moves target into quarantine vault, applies `0o600` POSIX mode, and writes `<hash>.manifest.json` preserving original path, permissions, and size (lines 505–618).
  - `unquarantine_file()` recalculates SHA-256 of the vault artifact before restoring to prevent tampering, moves file to target destination, restores original permissions (`os.chmod`), and deletes the manifest (lines 619–720).
- **Strict Safety Whitelists (`agent/arka_agent/active_response.py:98-166`, `backend/app/services/active_response_service.py:40-132`)**:
  - IP safety (`is_ip_protected`, `_validate_ip_safety`): Rejects loopback addresses (127.0.0.1, ::1), broadcast/unspecified (255.255.255.255, 0.0.0.0), configured backend hosts, and dynamically bound local network interfaces via `psutil.net_if_addrs()`.
  - PID safety (`is_pid_protected`): Rejects core system PIDs (0, 1, 2, 4), agent daemon PID (`os.getpid()`), parent PID (`os.getppid()`), and protected OS process names (`system`, `smss.exe`, `csrss.exe`, `wininit.exe`, `services.exe`, `lsass.exe`, `svchost.exe`, `explorer.exe`, `winlogon.exe`, `init`, `systemd`, `launchd`, `kthreadd`).
- **Active Response Backend Task Lifecycle & Persistence (`backend/app/services/active_response_service.py:134-445`)**:
  - `create_task()` verifies target safety, adds `ActiveResponseTask` and `AuditLog` to `AsyncSession`, commits, and returns the model.
  - `dispatch_alert_response()` triggers automated containment on `CRITICAL` or `BRUTE_FORCE_LOGIN` alerts, generating `ActiveResponseTask` and `AuditLog`.
  - `get_pending_tasks_for_agent()` polls pending tasks for an agent and transitions their state to `DISPATCHED` with a `dispatched_at` timestamp.
  - `update_task_result()` records execution returncode, stdout, stderr, execution timestamp, and creates completion audit log.

### 1.2 Vulnerability Detection & CVE Correlation (Milestone M6)
- **Semantic Version Normalization & PEP 440 Evaluation (`backend/app/services/vulnerability_engine.py:182-266`)**:
  - `normalize_version_string()` normalizes OS package version peculiarities into valid PEP 440 versions:
    - OpenSSL letter suffixes: `1.1.1t` -> `1.1.1.post20` (correctly evaluates `1.1.1t < 1.1.1u`).
    - Sudo/OpenSSH patch suffixes: `1.9.5p2` -> `1.9.5.post2`, `8.5p1` -> `8.5.post1` (correctly evaluates `1.9.5p2 <= 1.9.5p2` and `1.9.5p3 > 1.9.5p2`).
    - Debian/RPM release revisions: `7.88.1-10` -> `7.88.1.post10`.
    - Strips `.RELEASE`, `.final`, `.GA` suffixes.
  - `is_version_vulnerable()` handles compound clauses (comma-separated AND) and multi-branch OR specifications (`||`), e.g., `<5.2.20 || >=5.3.0, <5.3.18`.
- **CVSS v3.1 Base Score Calculation (`backend/app/services/vulnerability_engine.py:131-180`)**:
  - Implements FIRST.org CVSS v3.1 specification equation parsing vectors (`AV`, `AC`, `PR`, `UI`, `S`, `C`, `I`, `A`), computing ISS (Impact Sub-Score), Exploitability, Scope multiplier, and standard roundup.
- **Relational Persistence & Automated Alerting (`backend/app/services/vulnerability_engine.py:317-578`)**:
  - `seed_core_cves()` inserts or enriches 6 core enterprise CVE definitions (Log4Shell, OpenSSL, Curl, Sudo, OpenSSH RegreSSHion, Spring4Shell) into `cve_items` table.
  - `correlate_and_persist()` checks package inventory against active `CVEItem` records, persists `VulnerabilityFinding` records, generates `VulnerabilityScanReport` with severity breakdown metrics, and automatically dispatches `Alert` records (MITRE technique `T1190`, status `NEW`) for High and Critical vulnerabilities.
  - `update_finding_status()` provides complete lifecycle mutation (`ACTIVE` -> `MITIGATED` -> `RESOLVED` -> `FALSE_POSITIVE` -> `SUPPRESSED`) with `resolved_at` timestamps.
- **Package Vulnerability Collector (`agent/arka_agent/collectors/vulnerability.py:17-76`)**:
  - `PackageVulnerabilityScanner` delegates directly to `SyscollectorHarvester.get_installed_packages()` with zero hardcoded mock/fake package lists.

### 1.3 Zero Fake Data Compliance
- **Active Response Endpoints (`backend/app/api/v1/endpoints/active_response.py:46-148`)**:
  - `GET /api/v1/active_response/tasks` and `GET /api/v1/active_response` query `ActiveResponseService.get_tasks()` which issues SQL `select(ActiveResponseTask).where(...)`. Returns empty list `[]` when no tasks exist.
  - `GET /api/v1/active_response/agents/{agent_id}/pending` returns `[]` when no tasks are queued for the agent.
- **Vulnerability Endpoints (`backend/app/api/v1/endpoints/vulnerabilities.py:78-144`)**:
  - `GET /api/v1/vulnerabilities` queries `VulnerabilityEngine.get_tenant_findings()` which issues SQL `select(VulnerabilityFinding).where(...)`. Returns `[]` when no findings exist.
  - `GET /api/v1/vulnerabilities/reports/{agent_id}` queries `VulnerabilityEngine.get_agent_reports()` which issues SQL `select(VulnerabilityScanReport).where(...)`. Returns `[]` when no reports exist.

---

## 2. Logic Chain

1. **Premise 1 (Containment Realism)**: `agent/arka_agent/active_response.py` constructs real OS commands (`iptables`, `netsh`) and uses genuine `psutil`/`shutil`/`hashlib` system APIs with two-phase kill and SHA-256 quarantine vault. Therefore, containment logic is authentic and production-grade.
2. **Premise 2 (Containment Safety)**: Both agent executor and backend service enforce strict allowlist checks against loopback IPs, broadcast IPs, backend hosts, system PIDs, and system binaries. Therefore, self-DOS and unintended host disconnection are prevented.
3. **Premise 3 (Vulnerability Semantic Accuracy)**: `backend/app/services/vulnerability_engine.py` employs PEP 440 version specifier parsing with custom normalization for vendor version strings (letter suffixes, patch tags, release builds) and FIRST.org CVSS v3.1 vector calculations. Tests confirm vulnerable versions trigger findings while patched versions do not.
4. **Premise 4 (Relational Persistence & Lifecycle)**: Database models (`CVEItem`, `VulnerabilityFinding`, `VulnerabilityScanReport`, `ActiveResponseTask`, `AuditLog`) are mapped via SQLAlchemy 2.x declarative ORM. Services perform genuine database queries, state mutations, and commits.
5. **Premise 5 (Zero Fake Data Compliance)**: Endpoints and services return empty collections (`[]`) when querying empty database tables and never return hardcoded/mock fallback datasets.

---

## 3. Caveats

- **OS Firewall Execution in Unprivileged Containers**: Host firewall manipulation (`netsh` / `iptables`) requires appropriate administrative or `CAP_NET_ADMIN` privileges in deployment environments; executor provides graceful error handling and dry-run modes for unprivileged testing.
- **Kernel-level Rootkit Containment**: Active response executes in userspace and is designed for standard process/network/file isolation.

---

## 4. Conclusion

**Verdict: CLEAN**

Milestones M5 and M6 strictly adhere to all architectural, forensic integrity, and zero fake data requirements:
- Genuine active response containment executor with two-phase kill, native firewall manipulation, rollback timers, and SHA-256 manifest quarantine vault.
- Genuine vulnerability detection engine with PEP 440 semantic version normalization, FIRST.org CVSS v3.1 scoring, and automated alert generation.
- Full SQLAlchemy 2.x persistence and lifecycle state machines.
- 100% Zero fake data compliance across all endpoints and services.

---

## 5. Verification Method

### Test Commands
Execute the dedicated unit and integration test suites:
```bash
# Milestone M5 & M6 Agent & Backend test execution
pytest backend/tests/test_active_response_service.py backend/tests/test_vulnerability_engine.py agent/tests/test_active_response.py agent/tests/test_vulnerability_engine.py -v

# Full project test suite execution
pytest backend/tests agent/tests
```

### Invalidation Conditions
The CLEAN verdict would be invalidated if:
1. An endpoint returns pre-populated mock dictionaries when the database has zero records for a tenant.
2. `is_version_vulnerable` fails to distinguish patched versions from vulnerable versions for letter-suffix (`1.1.1t` vs `1.1.1u`) or patch-level (`1.9.5p2` vs `1.9.5p3`) packages.
3. Active response executor permits killing protected system PIDs (0, 1, 2, 4) or firewalling loopback/backend host IPs.
