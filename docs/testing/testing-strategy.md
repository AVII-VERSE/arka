# ARKA Testing Strategy & Test Pyramid

```
            / \
           /   \        E2E (Playwright)
          /     \       - Full MVP Workflow Validation
         /-------\
        /         \     Integration Tests
       /           \    - Ingestion -> Kafka -> OpenSearch
      /-------------\
     /               \  Unit Tests
    /                 \ - Schema Validation, Rule Engine, SQLite Buffer
   /-------------------\
```

---

## Test Automation Tools

- **Backend**: `pytest`, `pytest-asyncio`, `httpx`
- **Agent**: `pytest`, SQLite in-memory fixtures
- **Frontend**: `vitest`, `@testing-library/react`
- **End-to-End**: `playwright`
- **Security Scanning**: `bandit`, `pip-audit`, `detect-secrets`

---

## Running Test Suites

```bash
# Backend unit & API integration
cd backend && pytest

# Agent unit tests
cd agent && pytest

# Frontend component & state tests
cd frontend && npm test

# Playwright E2E full flow
npx playwright test
```
