# PR-015: Threat Hunting Playbooks Engine

**Branch:** `feature/15-threat-hunting-playbooks`
**Issue:** ISSUE-015
**Status:** [MERGED]

---

## Summary

Implements the Threat Hunting Playbooks Engine with a built-in MITRE ATT&CK-aligned playbook library. SOC analysts can list, create, execute, and track structured threat hunting workflows with step-by-step investigation queries.

## Built-in Playbook Library

| Playbook ID | Name | MITRE Tactic | Severity |
|---|---|---|---|
| PB-LATERAL-MOVEMENT-001 | Lateral Movement via Remote Services | Lateral Movement | HIGH |
| PB-CREDENTIAL-DUMPING-001 | Credential Dumping & Harvesting | Credential Access | CRITICAL |
| PB-DATA-EXFILTRATION-001 | Data Exfiltration Detection | Exfiltration | CRITICAL |
| PB-PERSISTENCE-001 | Persistence Mechanism Detection | Persistence | HIGH |

## Files Changed

### New Files
| File | Description |
|------|-------------|
| `backend/app/services/threat_hunting_service.py` | Threat Hunting Engine with 4 built-in MITRE ATT&CK playbooks |
| `backend/app/api/v1/endpoints/threat_hunting.py` | REST API CRUD + execution endpoints |
| `backend/tests/test_threat_hunting.py` | 10 unit tests covering all service methods and tenant isolation |

### Modified Files
| File | Description |
|------|-------------|
| `backend/app/api/v1/router.py` | Mounted `/threat_hunting` router |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/threat_hunting` | List all playbooks |
| `GET` | `/api/v1/threat_hunting/{playbook_id}` | Get specific playbook |
| `POST` | `/api/v1/threat_hunting` | Create custom playbook |
| `POST` | `/api/v1/threat_hunting/{playbook_id}/execute` | Execute playbook |
| `GET` | `/api/v1/threat_hunting/executions/list` | List execution records |
| `GET` | `/api/v1/threat_hunting/executions/{execution_id}` | Get execution details |

## Verification

- **Pytest:** 224 passed, 1 skipped
- **Ruff:** 0 errors
- **Bandit:** 0 Medium/High vulnerabilities
