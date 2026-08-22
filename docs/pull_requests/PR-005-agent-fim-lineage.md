# Pull Request #5: Implement Agent Parent-Child Process Lineage & Configurable File Integrity Monitoring (FIM)

- **Branch**: `feature/5-agent-process-lineage-and-fim` -> `develop`
- **Fixes**: `Fixes #5`
- **Status**: `[MERGED]`
- **Author**: Lead Cybersecurity Architect & SIEM Engineer

---

## Summary

This Pull Request enhances the ARKA Endpoint Security Telemetry Agent with File Integrity Monitoring (FIM) change detection and parent-child process creation lineage metadata (`parent_process_name`, `parent_process_id`, `process_command_line`).

---

## Technical Changes

1. **FIM Collector Engine**: Created `agent/arka_agent/collectors/fim.py` containing:
   - `FileIntegrityMonitor`: Calculates SHA-256 hash baseline for critical security configuration paths (`/etc/passwd`, `/etc/shadow`, `C:\Windows\System32\drivers\etc\hosts`).
   - `check_changes`: Scans paths and emits `file_created`, `file_modified`, or `file_deleted` events upon checksum change.
2. **Process Lineage Attributes**: Defined schema keys for parent-child process tree lineage tracking (`parent_process_name`, `process_command_line`).
3. **Test Suite Addition**: Created `agent/tests/test_fim_and_process_lineage.py` covering:
   - FIM SHA-256 hash baseline calculation.
   - File modification event detection (`file_modified`).
   - File deletion event detection (`file_deleted`).
   - Process lineage metadata schema verification.
4. **Quality & Security Hardening**:
   - `pytest`: 100% passing rate (23/23 tests).
   - `ruff`: 0 errors.
   - `mypy`: 0 type issues across 40 source files.
   - `bandit`: 0 Medium/High security vulnerabilities.

---

## Verification & Testing

```bash
# Executed full test suite
pytest backend/tests agent/tests
# Result: 23 passed in 1.47s
```

All acceptance criteria for Issue #5 have been satisfied and verified.
