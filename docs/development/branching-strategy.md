# ARKA Git Branching Strategy & Workflow

## Overview

The ARKA project uses a strict, structured Git branching model to ensure reliability, security, and traceability across releases.

```
feature/* ──┐
fix/*     ──┼──> develop ──> release/vX.Y.Z ──> main (v1.0.0)
security/* ─┘
```

---

## Branch Hierarchy

| Branch | Purpose | Direct Commits Allowed | Merge Source |
|---|---|---|---|
| `main` | Production stable release branch | **NO** | `release/*` or approved `develop` PR |
| `develop` | Active integration branch | **NO** | `feature/*`, `fix/*`, `security/*`, `docs/*` |
| `feature/*` | New functionality development | **YES** | Off `develop` |
| `fix/*` | Bug fixes | **YES** | Off `develop` |
| `security/*` | Security hardening / RBAC / isolation | **YES** | Off `develop` |
| `docs/*` | Technical documentation | **YES** | Off `develop` |
| `test/*` | Test infrastructure updates | **YES** | Off `develop` |
| `refactor/*` | Code cleanup and refactoring | **YES** | Off `develop` |

---

## Branching Workflow Rules

1. **Never develop directly on `main`**.
2. **Never force push (`git push -f`) to `main` or `develop`**.
3. **Pull Requests (PRs)** are mandatory for merging into `develop` or `main`.
4. **CI Merge Gates**: PRs must pass linting, type checks, unit/integration tests, and security scans before merging.
5. **Conventional Commits**: All commit messages must follow standard formatting (`feat:`, `fix:`, `security:`, `test:`, `docs:`, `refactor:`).
6. **No Secrets**: Never commit `.env` files, certificates, tokens, or private keys.

---

## Step-by-Step Feature Workflow

1. Fetch latest changes and update `develop`:
   ```bash
   git fetch origin
   git checkout develop
   git pull origin develop
   ```

2. Create feature branch:
   ```bash
   git checkout -b feature/event-ingestion
   ```

3. Make small, testable commits:
   ```bash
   git commit -m "feat(ingestion): add Kafka raw event producer"
   ```

4. Run local test and security checks:
   ```bash
   pytest
   ruff check .
   bandit -r backend/app
   ```

5. Push branch and open Pull Request:
   ```bash
   git push -u origin feature/event-ingestion
   ```
