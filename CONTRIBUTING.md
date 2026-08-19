# Contributing to ARKA

Thank you for your interest in contributing to ARKA (Advanced Real-time Kinetic Analytics).

---

## Code of Conduct

Maintain professional, constructive, and respectful communication in all interactions across issues, pull requests, and code reviews.

---

## Branching Strategy

ARKA follows a structured branching workflow:

- `main`: Production-stable branch. Never commit or push directly to `main`.
- `develop`: Integration branch where feature branches are merged.
- `feature/<name>`: New functionality (e.g., `feature/event-ingestion`).
- `fix/<name>`: Bug fixes (e.g., `fix/agent-reconnect-logic`).
- `security/<name>`: Hardening & access control (e.g., `security/tenant-rbac`).
- `docs/<name>`: Documentation updates (e.g., `docs/api-spec`).
- `test/<name>`: Testing infrastructure changes.

For full details, see [`docs/development/branching-strategy.md`](docs/development/branching-strategy.md).

---

## Conventional Commits

All commit messages must follow the [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>(<scope>): <short description>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `security`: Security enhancement or bug patch
- `test`: Adding or modifying tests
- `docs`: Documentation updates
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `perf`: Performance improvement
- `ci`: CI/CD workflow changes
- `chore`: Maintenance tasks

Examples:
- `feat(ingestion): add Kafka raw event producer`
- `fix(agent): handle SQLite queue disk full exception`
- `security(api): enforce tenant_id check on alert update endpoint`

---

## Pull Request Submission Checklist

Before submitting a Pull Request:

1. **Create Feature Branch**: Branch off `develop`.
2. **Write Tests**: Ensure unit and integration tests are added for your feature.
3. **Run Code Quality Checks**:
   - Python: `ruff check backend/` & `mypy backend/`
   - Frontend: `npm run lint` & `npm run type-check` inside `frontend/`
4. **Run Security Checks**:
   - `bandit -r backend/app`
   - `pip-audit`
5. **Update Documentation**: Synchronize doc files with any schema, API, or architectural changes.
6. **No Secrets**: Verify no credentials, tokens, or environment files are tracked.
7. **Passing CI**: Ensure all automated GitHub Actions checks pass cleanly.
