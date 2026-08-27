## 2026-08-26T08:50:25Z

You are teamwork_preview_worker #2 for Milestone M2 (R1: Rootcheck & System Anomaly Harvester).

Your Working Directory: d:/ARKA/.agents/worker_m2
Original Request Path: d:/ARKA/.agents/ORIGINAL_REQUEST.md
Project Scope Document: d:/ARKA/PROJECT.md
Survey Reference: d:/ARKA/.agents/explorer_survey_1/handoff.md § 4.2

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Scope & Exclusively Owned Files:
- `agent/arka_agent/collectors/rootcheck.py`
- `agent/tests/test_rootcheck_and_syscollector.py`

Tasks:
1. Initialize `progress.md` and `BRIEFING.md` in `d:/ARKA/.agents/worker_m2`.
2. Implement comprehensive `RootcheckScanner` in `agent/arka_agent/collectors/rootcheck.py`:
   - Known rootkit signature harvester (`scan_suspicious_files`) across Linux (Diamorphine, Reptile, Azazel, /dev/.udev, /dev/.shm, SUID/SGID binaries) and Windows (suspicious drivers, AppInit_DLLs, registry startup keys).
   - Hidden process detection (`scan_hidden_processes`) with dual-view cross-validation between `psutil.pids()` and raw `/proc` directory enumeration / OS signals.
   - Hidden / unmapped / promiscuous network socket scanner (`scan_listening_ports`) with promiscuous interface flag detection (`IFF_PROMISC` / `0x100`) and high-risk backdoor ports (31337, 6667, 4444, 12345, 65535).
   - System binary and preload tampering (`scan_system_binaries`) checking `/etc/ld.so.preload`, binary existence, and permission anomalies.
   - `run_full_scan()` aggregating all findings into standard `NormalizedEvent` dictionaries.
   - Robust error handling: graceful catch of `PermissionError` and `psutil.AccessDenied`.
3. Expand `agent/tests/test_rootcheck_and_syscollector.py` with multi-tier tests:
   - Tier 1: Suspicious file detection via `tmp_path`, backdoor port detection, clean state zero findings, full audit scan aggregation, platform dispatch.
   - Tier 2: Permission denied handling, process terminated mid-scan handling, empty path lists, IPv6/ephemeral ports, hidden process mock detection.
4. Verify all tests and static analysis pass:
   - `pytest agent/tests`
   - `ruff check agent`
   - `mypy agent/arka_agent`
   - `bandit -r agent/arka_agent -ll`
5. Write `handoff.md` with complete test output, commands, and verification results, then send a message when done.
