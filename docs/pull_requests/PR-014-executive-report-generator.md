# PR-014: Automated SOC Compliance & Executive Security Report Generator

**Branch:** `feature/14-executive-report-generator`
**Issue:** ISSUE-014
**Status:** [MERGED]

---

## Summary

Implements the Automated SOC Compliance & Executive Security Report Generator, enabling executive-level security posture briefings with aggregated CIS compliance scores, alert severity breakdowns, vulnerability counts, and active endpoint metrics.

## Files Changed

### New Files
| File | Description |
|------|-------------|
| `backend/app/services/report_generator_service.py` | Executive Report Generator service aggregating SIEM telemetry |
| `backend/app/api/v1/endpoints/reports.py` | REST API endpoints for report listing, generation, and HTML download |
| `backend/tests/test_report_generator.py` | Unit tests for report generation and listing |

### Modified Files
| File | Description |
|------|-------------|
| `backend/app/api/v1/router.py` | Mounted `/reports` router with `Executive Security Reports` tag |
| `backend/tests/test_pipeline.py` | Fixed cross-tenant isolation assertions and dry_run quarantine handling |
| `backend/tests/test_e2e_scenarios.py` | Added `# ruff: noqa: PLR0915` for long integration test functions |
| `agent/tests/test_vulnerability_engine.py` → `agent/tests/test_vulnerability_collector.py` | Renamed to avoid module name collision |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/reports` | List executive reports for tenant |
| `POST` | `/api/v1/reports/generate` | Generate new executive security report |
| `GET` | `/api/v1/reports/{report_id}/download_html` | Download HTML briefing |

## Verification

- **Pytest:** 209 passed, 1 skipped (SUID on Windows)
- **Ruff:** 0 errors
- **Bandit:** 0 Medium/High vulnerabilities
