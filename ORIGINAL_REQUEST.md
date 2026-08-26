# Original User Request

## 2026-08-26T07:49:25Z

<USER_REQUEST>
# Teamwork Project Prompt — ARKA Enterprise SIEM & XDR Platform

> Status: Launched
> Goal: Implement comprehensive Enterprise SIEM, EDR & XDR capabilities into ARKA (Advanced Real-time Kinetic Analytics)
> Product Title: **ARKA** (Do not rename to Wazuh)

Implement full enterprise SIEM, EDR, and XDR capabilities into the existing **ARKA** codebase across 60 foundational cybersecurity modules, maintaining strict production code quality, zero fake data, 100% test coverage, and PostgreSQL/Kafka/OpenSearch persistence.

Working directory: d:/ARKA
Integrity mode: development

## Requirements

### R1. Rootcheck & System Anomaly Harvester
Implement a security collector module in `agent/arka_agent/collectors/rootcheck.py` that scans for hidden processes, promiscuous network sockets, hidden files in system directories, and system call anomalies, emitting normalized security events into the ARKA pipeline.

### R2. Security Configuration Assessment (SCA) & CIS Benchmarks Engine
Implement a CIS benchmark compliance scanner in `agent/arka_agent/collectors/sca.py` and `backend/app/services/sca_engine.py` that checks OS configuration parameters (password policies, SSH hardening, registry settings) against policy rules and computes live compliance scores (Pass/Fail/N/A).

### R3. Syscollector System Inventory Harvester
Implement a hardware, software, user, and network socket inventory collector in `agent/arka_agent/collectors/syscollector.py` and expose REST APIs in `backend/app/api/v1/endpoints/inventory.py` to index inventory snapshots in OpenSearch.

### R4. Automated Active Response Container
Implement automated response actions in `agent/arka_agent/active_response.py` and `backend/app/services/active_response_service.py` to trigger IP blocking (firewall rule addition), process termination, and account locking upon High/Critical alert generation.

### R5. Vulnerability Detection & CVE Correlation Engine
Implement a vulnerability scanner in `backend/app/services/vulnerability_engine.py` that cross-references installed software inventory against NVD CVE feeds and CVSS v3 severity metrics.

## Acceptance Criteria

### Automated Tests
- [ ] `pytest backend/tests agent/tests` passes 100% (all existing + new tests).
- [ ] `ruff check backend agent` reports 0 errors.
- [ ] `mypy backend app agent/arka_agent` reports 0 type errors.
- [ ] `bandit -r backend/app agent/arka_agent -ll` reports 0 Medium/High vulnerabilities.

### System Verification
- [ ] All 3 background services (Backend Gateway, SOC Dashboard, Agent Daemon) remain 100% operational.
- [ ] Real telemetry is processed with zero fake/hardcoded values.

</USER_REQUEST>
