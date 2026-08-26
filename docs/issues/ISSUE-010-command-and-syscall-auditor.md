# Issue #10: Implement Command & Syscall Auditor (Auditd & Execve Telemetry Harvester)

- **Status**: `[RESOLVED]`
- **Severity**: `HIGH`
- **Component**: `agent/arka_agent/collectors/command_auditor.py`, `backend/app/services/command_audit_service.py`, `backend/app/api/v1/endpoints/command_audit.py`
- **Reporter**: Lead Cybersecurity Architect
- **Target Branch**: `feature/10-command-and-syscall-auditor`

---

## Objective

Implement Command Execution & System Call Auditor into ARKA:
1. **Endpoint Command Auditor**: Endpoint collector (`agent/arka_agent/collectors/command_auditor.py`) harvesting command line executions, user context (UID/EUID/GID), parent process PID, binary path, and system call events (`execve`).
2. **Command Audit & Privilege Escalation Service**: Backend service (`backend/app/services/command_audit_service.py`) detecting suspicious commands (e.g. `whoami`, `cat /etc/shadow`, `powershell -enc`, `nc -e /bin/bash`, `chmod 777`) and privilege escalation attempts.
3. **Command Audit REST API**: REST API endpoints `/api/v1/command_audit` to query audited command telemetry and privilege escalation events.

---

## Acceptance Criteria

- [ ] `agent/arka_agent/collectors/command_auditor.py` collects command line executions and user security context.
- [ ] `backend/app/services/command_audit_service.py` identifies suspicious commands and MITRE ATT&CK TTPs.
- [ ] `backend/app/api/v1/endpoints/command_audit.py` provides REST API endpoint.
- [ ] `agent/tests/test_command_auditor.py` test suite passes 100%.
- [ ] Full `pytest` test suite passes 100%.
- [ ] `ruff`, `mypy`, `bandit` static checks pass with 0 errors/issues.
