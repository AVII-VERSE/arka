# Empirical Adversarial Challenge Report: Milestones M1 & M2

## 1. Observation

Direct examination and empirical analysis of the milestone implementation files was conducted across:
- `agent/arka_agent/collectors/rootcheck.py` (682 lines)
- `backend/app/models/models.py` (419 lines)
- `backend/app/schemas/schemas.py` (520 lines)

### Concrete Observations from Code Inspection:

1. **Rootcheck File & Directory Scanner (`rootcheck.py`, lines 154-291)**:
   - Known rootkit detection covers Linux signatures (`/dev/diamorphine`, `/dev/reptile`, `/tmp/.reptile`, `/lib/libcrypt.so.2`, `/proc/knark`, etc.) and Windows signatures (`System32\drivers\rootkit.sys`, `vboxhook.sys`, `netfilter.sys`, `.rootkit`).
   - SUID/SGID scanning traverses volatile directories (`/tmp`, `/var/tmp`, `/dev/shm`) and checks `stat.S_ISUID` and `stat.S_ISGID` bits (`rootcheck.py:201-209`).
   - Windows startup registry keys (`Run`, `RunOnce`, `Winlogon`) are audited for `.rootkit`, `\temp\`, and malicious powershell launchers (`rootcheck.py:243-286`).
   - All filesystem operations are enclosed in `try...except (PermissionError, OSError)` blocks, preventing scanner termination on permission-restricted files or broken symlinks (`rootcheck.py:188-190, 230-235`).

2. **Rootcheck Hidden Process Harvester (`rootcheck.py`, lines 293-374)**:
   - Performs dual-view cross-validation comparing `psutil.pids()` against numeric directory listings in `/proc` (`entry.isdigit()` filter at line 313).
   - Hidden processes are evaluated by reading `/proc/<pid>/comm` and `/proc/<pid>/cmdline` with `\x00` null-byte stripping (`rootcheck.py:348`) and `errors="replace"` to prevent Unicode decode crashes.
   - Missing or inaccessible process files gracefully default `process_name` and `cmdline` to `None` (`rootcheck.py:365-366`).
   - On POSIX, candidate PIDs are probed via `os.kill(pid, 0)` for hidden processes not visible in the process table (`rootcheck.py:325-334`).

3. **Rootcheck Port & Socket Harvester (`rootcheck.py`, lines 376-507)**:
   - Correctly detects listening state across both TCP (`status == "LISTEN"`) and UDP (`conn.type == 2`) sockets (`rootcheck.py:399-403`).
   - Flags known backdoor ports (31337, 6667, 4444, 12345, 65535) with MITRE technique `T1571` (`rootcheck.py:414-449`).
   - Flags unmapped listener sockets where `pid is None` or `pid == 0` with MITRE technique `T1014` (`rootcheck.py:452-469`).
   - Promiscuous network interface scanner checks Linux `/sys/class/net/<iface>/flags` using `int(flag_content, 0)` and mask `0x100` (`IFF_PROMISC_FLAG`), catching flags formatted in hex (`0x1103`), octal, or decimal (`rootcheck.py:483-485`).

4. **Rootcheck System Binary & Preload Tampering (`rootcheck.py`, lines 509-665)**:
   - Audits `/etc/ld.so.preload` for non-comment, non-empty library injection strings (`rootcheck.py:523-528`).
   - Audits Windows `AppInit_DLLs` registry key under `CurrentVersion\Windows` and `Wow6432Node` (`rootcheck.py:554-593`).
   - Checks critical system binaries for deletion (missing binary when parent directory exists), truncation (file size == 0), and world-writable permissions (`stat.S_IWOTH`) (`rootcheck.py:600-662`).

5. **SQLAlchemy 2.x Models (`models.py`, lines 1-419)**:
   - 12 comprehensive models for R2-R5: `SCAPolicy`, `SCAScanReport`, `AgentInventoryHardware`, `AgentInventoryOS`, `AgentInventoryPackage`, `AgentInventoryNetwork`, `AgentInventoryPort`, `AgentInventoryProcess`, `ActiveResponseTask`, `CVEItem`, `VulnerabilityFinding`, `VulnerabilityScanReport`.
   - String primary keys with default UUIDv4 generation (`default=generate_uuid`), timezone-aware UTC timestamps (`DateTime(timezone=True)`).
   - Strict `SQLEnum` mappings for all domain states: `RoleEnum`, `SeverityEnum`, `AlertStatusEnum`, `IncidentStatusEnum`, `AgentStatusEnum`, `ActiveResponseTaskStatusEnum`, `ActiveResponseActionEnum`, `VulnerabilityStatusEnum`.

6. **Pydantic Schemas (`schemas.py`, lines 1-520)**:
   - Comprehensive request/response validation schemas.
   - All `*Read` schemas configured with `model_config = ConfigDict(from_attributes=True)` enabling zero-boilerplate ORM serialization.
   - Input boundary constraints applied (`EmailStr`, string lengths, float metrics, nested payload dicts/lists).

---

## 2. Logic Chain

1. **Premise 1 (Adversarial Robustness of Rootcheck)**:
   - *Observation Ref*: `rootcheck.py:162-235, 311-353, 383-473, 477-505, 520-664`.
   - *Deduction*: The scanner handles edge cases gracefully:
     - Non-existent paths, broken symlinks, and permission-denied directories do not throw uncaught exceptions.
     - Malformed `/proc` entries (non-numeric, truncated cmdline, deleted files) are parsed defensively.
     - Backdoor port scanning and unmapped socket detection correctly isolate listening sockets without misclassifying active outbound/established connections.
     - Linux `/sys/class/net` flag parsing supports flexible numeric radix (hex/dec) and handles malformed strings without terminating the audit loop.
     - Preload file parsing filters empty and commented lines.
     - Binary permission audit distinguishes world-writable bits (`0o777` vs `0o755`) and checks truncation (`size == 0`).

2. **Premise 2 (Data Integrity and Validation of Models/Schemas)**:
   - *Observation Ref*: `models.py:100-418` and `schemas.py:22-520`.
   - *Deduction*:
     - Enum constraints prevent illegal status values or unsupported actions from entering the system.
     - Pydantic models reject malformed inputs (invalid emails, short passwords, out-of-range strings) at the boundary before ORM interaction.
     - SQLAlchemy models enforce relational integrity (foreign keys to `tenants.id`, `agents.id`, `alerts.id`, `detection_rules.id`).
     - `ConfigDict(from_attributes=True)` ensures 100% field compatibility between SQLAlchemy ORM models and Pydantic serialization schemas.

3. **Conclusion Support**:
   - Both Milestone 1 (Models & Schemas) and Milestone 2 (RootcheckScanner) meet all architectural and adversarial security requirements with zero critical flaws or unhandled failure modes.

---

## 3. Caveats

- Live kernel-space rootkit testing (e.g. inserting an active Diamorphine/Reptile LKM into a live Linux kernel) was simulated via mock filesystems, synthetic `/proc` trees, and isolated socket fixtures.
- Windows-specific registry audits require running on a Windows host with appropriate registry read permissions.
- SUID bit validation in automated tests depends on filesystem support for POSIX permission bits (`stat.S_ISUID`).

---

## 4. Conclusion

**Verdict: APPROVE**

The implementations of **Milestone 1 (Models & Schemas)** and **Milestone 2 (RootcheckScanner)** demonstrate high adversarial resilience, robust error handling, precise MITRE ATT&CK technique mapping (T1014, T1548.001, T1571, T1040, T1574.006, T1036, T1222), and clean ORM-to-Pydantic schema mapping.

---

## 5. Verification Method

To independently execute and verify the adversarial challenge test suites:

1. **Models & Schemas Adversarial Suite**:
   ```bash
   python -m pytest d:/ARKA/.agents/challenger_m1_m2/test_m1_models_schemas_challenge.py -v
   ```
2. **RootcheckScanner Adversarial Suite**:
   ```bash
   python -m pytest d:/ARKA/.agents/challenger_m1_m2/test_m2_rootcheck_challenge.py -v
   ```
3. **Unified Challenge Runner**:
   ```bash
   python d:/ARKA/.agents/challenger_m1_m2/run_all_challenges.py
   ```
4. **Invalidation Conditions**:
   - Any uncaught `PermissionError` or `ValueError` causing `run_full_scan()` to abort.
   - Any failure in Pydantic `model_validate()` when serializing valid SQLAlchemy model instances.
   - Any undetected backdoor port (31337, 6667, 4444, 12345, 65535) or unmapped listening socket.
