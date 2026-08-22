# Issue #5: Implement Agent Parent-Child Process Lineage & Configurable File Integrity Monitoring (FIM)

- **Status**: `[RESOLVED]`
- **Severity**: `HIGH`
- **Component**: `agent/arka_agent/collectors/fim.py`, `agent/arka_agent/collectors/windows_event_log.py`, `agent/arka_agent/collectors/linux_syslog.py`
- **Reporter**: Lead Cybersecurity Architect
- **Target Branch**: `feature/5-agent-process-lineage-and-fim`

---

## Objective

Enhance the ARKA Endpoint Security Telemetry Agent with parent-child process tree lineage metadata (`parent_process_name`, `parent_process_id`, `process_command_line`) and a configurable File Integrity Monitoring (FIM) harvester. FIM must monitor critical system configuration files (`/etc/passwd`, `/etc/shadow`, `C:\Windows\System32\drivers\etc\hosts`), calculate SHA-256 hashes, and emit `file_integrity` security events upon modification, creation, or deletion without excessive resource consumption.

---

## Current Behavior

Agent collects basic OS EventLogs and Syslogs, but lacks parent-child process creation hierarchy tracing and File Integrity Monitoring (FIM) hash change detection.

---

## Expected Behavior

1. `FileIntegrityMonitor` checks configured target file paths, computes SHA-256 checksums, and emits `file_integrity` events when hash changes occur.
2. OS collectors extract parent process name (`parent_process_name`), parent PID (`parent_process_id`), and full execution command line (`process_command_line`).
3. FIM avoids monitoring the entire filesystem by default to minimize CPU/disk overhead.
4. Unit tests in `agent/tests/test_fim_and_process_lineage.py` pass 100%.

---

## Acceptance Criteria

- [ ] `agent/arka_agent/collectors/fim.py` implements configurable file integrity hashing and change detection.
- [ ] OS collectors populate process lineage fields (`parent_process_name`, `process_command_line`).
- [ ] FIM emits `file_integrity` event on file modification/creation/deletion.
- [ ] Unit tests in `agent/tests/test_fim_and_process_lineage.py` pass 100%.
- [ ] Pytest suite passes 100%.

---

## Testing Plan

1. **Unit Tests**: `agent/tests/test_fim_and_process_lineage.py` testing file creation/modification detection, SHA-256 hash calculation, and process lineage field extraction.
