# Security Architecture Blueprint — ARKA

## Security Principles

1. **Defense in Depth**: Security controls applied at agent, network, API gateway, application logic, and database layers.
2. **Strict Multi-Tenancy**: Every data access path is isolated by `tenant_id`. No cross-tenant query execution is possible.
3. **Zero Trust Agent Authentication**: Agents authenticate using HMAC tokens or client mTLS certificates.
4. **Least Privilege RBAC**: Fine-grained authorization on backend REST routes based on user role.

---

## Authentication & Authorization Architecture

```
[SOC Analyst] ──> [React Frontend] ──> [Bearer JWT Token] ──> [FastAPI Middleware]
                                                                      │
                                                   ┌──────────────────┴──────────────────┐
                                                   ▼                                     ▼
                                       [Verify Token Signature]              [Check Role Permission]
                                       Keycloak OIDC / JWT                   `SECURITY_ANALYST`
                                                   │                                     │
                                                   └──────────────────┬──────────────────┘
                                                                      ▼
                                                         [Enforce Tenant Scope]
                                                         WHERE tenant_id = :tenant
```

---

## Role-Based Access Control (RBAC) Hierarchy

| Role | Permissions |
|---|---|
| `SUPER_ADMIN` | Global platform administration, tenant provisioning, system audit logs. |
| `TENANT_ADMIN` | Tenant user management, agent token generation, detection rule configuration. |
| `SECURITY_ANALYST` | View events, manage alert lifecycle status, create and investigate incidents. |
| `SECURITY_VIEWER` | Read-only access to dashboard statistics, events, and alerts. |

---

## Agent Security & Enrollment

1. **Enrollment**: Administrator generates a short-lived enrollment token for a tenant.
2. **Registration**: Agent connects to `/api/v1/agents/enroll` presenting enrollment token and agent metadata (hostname, OS, MAC address).
3. **Credential Issuance**: Server registers agent ID and returns a dedicated Agent Secret Token or signs an mTLS certificate.
4. **Heartbeat & Event Auth**: Subsequent requests include `X-ARKA-Agent-Token` header or mTLS cert for verification.
