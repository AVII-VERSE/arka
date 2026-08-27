# Issue #11: Implement Container & Cloud Security Harvesters (Docker/K8s & CloudTrail Harvester)

- **Status**: `[IN_PROGRESS]`
- **Severity**: `HIGH`
- **Component**: `agent/arka_agent/collectors/cloud_container.py`, `backend/app/services/cloud_container_service.py`, `backend/app/api/v1/endpoints/cloud_container.py`
- **Reporter**: Lead Cybersecurity Architect
- **Target Branch**: `feature/11-container-and-cloud-harvesters`

---

## Objective

Implement Container & Cloud Security Telemetry Harvesters into ARKA:
1. **Container & Cloud Security Collector**: Agent collector (`agent/arka_agent/collectors/cloud_container.py`) harvesting Docker container events (`container_create`, `container_die`, `privileged_execution`), Kubernetes Pod audit logs, and Cloud API call logs (AWS CloudTrail / GCP Audit).
2. **Container Escape & Cloud Misconfiguration Service**: Backend analytics service (`backend/app/services/cloud_container_service.py`) detecting privileged container escapes (`hostPID=true`, `hostNetwork=true`, `capabilities: [SYS_ADMIN]`), root user container runs, and unauthorized IAM role assumptions.
3. **Cloud & Container REST API**: REST API endpoints `/api/v1/cloud_container` to query container inventories, Pod security posture, and cloud audit logs.

---

## Acceptance Criteria

- [ ] `agent/arka_agent/collectors/cloud_container.py` collects container lifecycle and cloud audit telemetry.
- [ ] `backend/app/services/cloud_container_service.py` detects container escape risks and cloud security anomalies.
- [ ] `backend/app/api/v1/endpoints/cloud_container.py` provides REST API endpoint.
- [ ] `agent/tests/test_cloud_container.py` test suite passes 100%.
- [ ] Full `pytest` test suite passes 100%.
- [ ] `ruff`, `mypy`, `bandit` static checks pass with 0 errors/issues.
