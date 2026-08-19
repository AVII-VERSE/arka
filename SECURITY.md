# Security Policy — ARKA SIEM Platform

ARKA is built with a security-first philosophy. We appreciate security researchers, maintainers, and community members who help maintain the integrity, confidentiality, and availability of our platform.

---

## Supported Versions

Only the latest active major/minor release branch receives security updates.

| Version | Supported          |
| ------- | ------------------ |
| `v0.1.x` (develop) | :white_check_mark: |
| `< v0.1.0`         | :x:                |

---

## Reporting a Vulnerability

**Do NOT report security vulnerabilities via public GitHub issues.**

If you discover a potential security flaw in ARKA (such as authentication bypass, privilege escalation, IDOR, tenant data leak, or injection vulnerabilities):

1. **Email Security Team**: Send an encrypted email to `security@arka-siem.org` (or contact repository maintainers directly).
2. **Include Technical Details**:
   - Component affected (`backend`, `agent`, `ingestion API`, `OpenSearch mapping`, `frontend`).
   - Detailed proof-of-concept (PoC) steps or script.
   - Impact assessment (e.g., impact on tenant isolation or unauthorized data exposure).
   - Any proposed remediation or patch suggestions.

---

## Reporting Guidelines & Constraints

- **Controlled Environment Only**: All security research must be conducted against your own controlled local instance (e.g., Docker Compose stack).
- **No Destructive Attacks**: Do not attempt denial of service (DoS), automated destructive attacks, or mass spamming.
- **Data Privacy**: Respect tenant data boundaries and user privacy at all times.

---

## Security SLA & Response Timeline

- **Acknowledgement**: Within 24 hours of receiving the vulnerability report.
- **Initial Triage & Assessment**: Within 72 hours.
- **Patch & Fix Release**:
  - **CRITICAL / HIGH**: Patch released within 7 days.
  - **MEDIUM / LOW**: Patch released within 30 days or next scheduled release.

---

## Security Architectural Guarantees

- **No Hardcoded Credentials**: Source code must never contain API keys, JWT secrets, passwords, or private certificates.
- **Tenant Isolation**: Every database query, Kafka payload, and OpenSearch search request must be explicitly scoped by `tenant_id`.
- **Backend Authorization Enforcement**: Frontend routing logic is never trusted for authorization; all access control checks occur on the backend API layer.
