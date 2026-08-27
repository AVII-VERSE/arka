# Milestone M2 (R1: Rootcheck & System Anomaly Harvester) Handoff Report

**Agent**: `worker_m2` (teamwork_preview_worker #2)
**Date**: 2026-08-26
**Milestone**: M2 — R1: Rootcheck & System Anomaly Harvester
**Exclusively Owned Files**:
- `agent/arka_agent/collectors/rootcheck.py`
- `agent/tests/test_rootcheck_and_syscollector.py`

---

## 1. Observation

### 1.1 Pre-existing State & Gaps
Direct inspection of the codebase identified the following starting state and requirements:
1. **Collector Architecture (`agent/arka_agent/collectors/rootcheck.py`)**:
   - Needed full `BaseCollector` integration (`super().__init__(name="rootcheck", enabled=enabled)` and `collect() -> list[dict[str, Any]]`).
   - Required rootkit artifact signature detection across Linux (Diamorphine, Reptile, Azazel, adore-ng, Knark, t0rn, Ebury, `/dev/.udev`, `/dev/.shm`, `/tmp/.*`, `/var/tmp/.*`) and Windows (`System32\drivers` rootkits, `System32\config\.hidden`, `ProgramData\.rootkit`, `Temp\.rootkit`).
   - Required SUID/SGID binary anomaly detection across volatile directories (`/tmp`, `/var/tmp`, `/dev/shm`) checking `stat.S_ISUID | stat.S_ISGID`.
   - Required Windows Registry persistence detection (`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, `RunOnce`, `Winlogon`).
   - Required dual-view hidden process detection comparing `psutil.pids()` against raw `/proc/[0-9]+` enumeration and kernel signal 0 (`os.kill(pid, 0)`) probing.
   - Required socket anomaly scanning for backdoor ports (`31337`, `6667`, `4444`, `12345`, `65535`), unmapped sockets (`pid is None`), and Linux promiscuous interface detection via `/sys/class/net/<iface>/flags` (`IFF_PROMISC` / `0x100`).
   - Required dynamic linker preload tampering detection (`/etc/ld.so.preload` and Windows `AppInit_DLLs`), missing critical binary detection (`/bin/ps`, `/bin/netstat`, `/bin/ls`, `/bin/login`, `/usr/sbin/sshd`, `/bin/su`, `/usr/bin/sudo`, `cmd.exe`, `svchost.exe`, `lsass.exe`), 0-byte truncation detection, and world-writable permission anomalies (`stat.S_IWOTH`).
   - Required standard `NormalizedEvent` schema generation with structured metadata and MITRE ATT&CK technique tags (`T1014`, `T1548.001`, `T1547.001`, `T1571`, `T1040`, `T1574.006`, `T1036`, `T1222`).
   - Required robust exception handling for `PermissionError`, `psutil.AccessDenied`, `psutil.NoSuchProcess`, `psutil.ZombieProcess`, and `OSError`.

2. **Test Suite (`agent/tests/test_rootcheck_and_syscollector.py`)**:
   - Required multi-tier coverage: Tier 1 (Baseline and detection) and Tier 2 (Robustness, permissions, edge cases).

---

## 2. Logic Chain

1. **BaseCollector Interface Compliance**:
   - `RootcheckScanner` inherits `BaseCollector` and implements `collect()`. When `self.enabled` is `True`, `collect()` calls `self.run_full_scan()`; when `False`, it returns `[]`.
2. **Normalized Telemetry Schema**:
   - Every detected anomaly is wrapped in a standard `NormalizedEvent` dictionary with `event_id`, `tenant_id`, `agent_id`, `timestamp`, `source_type="rootcheck"`, `host`, `event_type="rootkit_detection"`, `action`, `severity`, `message`, `metadata`, and `ingested_at`.
3. **Cross-Platform Dependency Inversion for Hermetic Testing**:
   - All scan targets are parameterized with sensible platform defaults (`suspicious_paths`, `proc_dir`, `sys_net_dir`, `preload_path`, `critical_binaries`, `suid_scan_dirs`) while allowing unit tests to inject fixtures (`tmp_path`, custom connection lists, candidate PID sets) without requiring elevated root/SYSTEM privileges.
4. **Dual-View Process Verification**:
   - Cross-references `psutil.pids()` against raw directory entries in `proc_dir`. PIDs present in filesystem `/proc` or responding to kernel signal 0 but missing from API process tables are flagged as `hidden_process_detected` (MITRE `T1014`).
5. **Network Socket & Promiscuous Mode Detection**:
   - Inspects both TCP and UDP listening sockets. Sockets bound to known backdoor ports (`BACKDOOR_PORTS = (31337, 6667, 4444, 12345, 65535)`) or lacking owning user-space PIDs are flagged.
   - Reads `/sys/class/net/<iface>/flags` and evaluates bitwise `IFF_PROMISC_FLAG = 0x100`.
6. **Binary Preload and Integrity Audit**:
   - Dynamic linker preload `/etc/ld.so.preload` and Windows `AppInit_DLLs` are parsed for unauthorized libraries.
   - Critical system binaries are verified for existence, non-zero size, and absence of world-writable permissions.

---

## 3. Caveats

- **Operating System Specific Features**: On non-POSIX filesystems or platforms where `chmod` does not support SUID bits or world-writable bits, tests gracefully use `pytest.skip` to prevent false failures while maintaining full coverage when run on POSIX.
- **Root Privileges in Production**: In production environments, standard users running the scanner will encounter permission restrictions on certain kernel files. The implementation catches `PermissionError` and `psutil.AccessDenied` gracefully, logging debug diagnostics without crashing.

---

## 4. Conclusion

The `RootcheckScanner` collector in `agent/arka_agent/collectors/rootcheck.py` and the accompanying multi-tier test suite in `agent/tests/test_rootcheck_and_syscollector.py` are fully implemented, verified, and strictly conform to all project requirements and safety guardrails. Zero dummy or facade implementations were used; all detection mechanisms maintain genuine state and evaluation logic.

---

## 5. Verification Method

### 5.1 Test Execution Commands
Run the complete agent and collector test suite:
```powershell
$env:PYTHONPATH="d:\ARKA\backend;d:\ARKA\agent"
& "d:\ARKA\backend\.venv\Scripts\python.exe" -m pytest agent/tests -v
```

Run test suite specifically targeting Rootcheck & Syscollector:
```powershell
& "d:\ARKA\backend\.venv\Scripts\python.exe" -m pytest agent/tests/test_rootcheck_and_syscollector.py -v
```

### 5.2 Static Analysis & Quality Verification
Run Ruff lint check:
```powershell
& "d:\ARKA\backend\.venv\Scripts\ruff.exe" check agent
```

Run Mypy type verification:
```powershell
& "d:\ARKA\backend\.venv\Scripts\mypy.exe" agent/arka_agent
```

Run Bandit security scan:
```powershell
& "d:\ARKA\backend\.venv\Scripts\bandit.exe" -r agent/arka_agent -ll
```

### 5.3 Test Inventory in `test_rootcheck_and_syscollector.py` (28 Total Tests)
- `test_rootcheck_base_collector_interface`: Validates `BaseCollector` inheritance and attributes.
- `test_rootcheck_scanner_execution`: Validates suspicious rootkit file detection.
- `test_suspicious_file_detection_directory`: Validates suspicious rootkit directory detection.
- `test_suspicious_suid_binary_detection`: Validates SUID/SGID binary detection in volatile directories.
- `test_backdoor_port_detection`: Validates backdoor ports (31337, 6667).
- `test_all_backdoor_ports_flagged`: Validates all ports in `BACKDOOR_PORTS` (31337, 6667, 4444, 12345, 65535).
- `test_unmapped_listening_socket_detection`: Validates unmapped listener sockets.
- `test_udp_listening_socket_detection`: Validates UDP listening sockets (`SOCK_DGRAM`).
- `test_promiscuous_interface_detection`: Validates `IFF_PROMISC` flag (`0x100`) detection.
- `test_promiscuous_interface_corrupted_flags`: Validates non-integer/corrupted flag files handling.
- `test_preload_tampering_detection`: Validates `/etc/ld.so.preload` malicious library injection.
- `test_preload_tampering_empty_or_comments`: Validates clean/commented preload ignore logic.
- `test_critical_system_binary_missing`: Validates missing binary alert when parent directory exists.
- `test_critical_system_binary_zero_bytes`: Validates 0-byte truncated binary detection.
- `test_critical_system_binary_world_writable`: Validates world-writable binary detection (`S_IWOTH`).
- `test_critical_binary_nonexistent_parent_skipped`: Validates missing parent directory handling.
- `test_clean_system_zero_findings`: Validates zero false positives on clean system.
- `test_full_audit_scan_aggregation`: Validates `run_full_scan()` and `collect()` aggregation.
- `test_collector_disabled_returns_empty`: Validates `collect()` when `enabled=False`.
- `test_platform_dispatch`: Validates platform default paths and binary targets.
- `test_hidden_process_mock_detection`: Validates `/proc` vs `psutil.pids()` dual-view cross-validation.
- `test_hidden_process_candidate_pid_probing`: Validates candidate PID probing logic.
- `test_permission_denied_handling`: Validates `PermissionError` and `psutil.AccessDenied` resilience.
- `test_process_terminated_mid_scan`: Validates mid-scan process exit handling.
- `test_empty_paths_and_connections`: Validates empty inputs execution.
- `test_ipv6_and_ephemeral_ports`: Validates IPv6 backdoor listening and non-listening established socket filtering.
- `test_psutil_process_access_denied_on_backdoor_port`: Validates `NoSuchProcess`/`AccessDenied` on `psutil.Process(pid)`.
- `test_syscollector_inventory_harvesting`: Validates Syscollector hardware, OS, network, and process inventory.
