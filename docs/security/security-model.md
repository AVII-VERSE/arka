# ARKA Security Model & Threat Assessment

## Threat Model & Controls

| Threat Vector | Mitigation Strategy | Enforcement Mechanism |
|---|---|---|
| **Unauthorized Event Injection** | Agent token / mTLS authentication | FastAPI auth middleware |
| **Tenant Cross-Contamination** | Mandatory `tenant_id` query scoping | SQLAlchemy async session filters & OpenSearch aliases |
| **Log Tampering / Replay** | Immutable UUIDv4 event IDs & cryptographic signatures | Duplicate event checker in Redis |
| **API Denial of Service** | Sliding window rate limits per tenant/IP | Redis rate-limiting middleware |
| **Data Leakage in Transit** | HTTPS (TLS 1.3) / mTLS forced | Nginx reverse proxy rules |
| **Privilege Escalation** | Rigid RBAC check on every REST endpoint | Pydantic / FastAPI dependency injection |

---

## Data Privacy & Confidentiality

ARKA is designed for security telemetry analysis. Agent collectors filter sensitive fields (passwords, credit card numbers, authorization headers) at source before transmission to avoid sensitive data exposure.
