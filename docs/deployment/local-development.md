# Local Development Setup Guide — ARKA

## System Requirements

- **OS**: Linux, macOS, or Windows 10/11 (WSL2 / PowerShell)
- **Docker**: Docker Desktop or Docker Engine v24+ with Docker Compose v2+
- **Python**: 3.12 or higher
- **Node.js**: 20 LTS or higher

---

## Environment Setup Steps

1. **Clone Repository & Copy Environment Template**:
   ```bash
   git clone https://github.com/AVII-VERSE/arka.git
   cd arka
   cp .env.example .env
   ```

2. **Boot Core Services with Docker Compose**:
   ```bash
   docker compose up -d postgres kafka opensearch redis keycloak
   ```

3. **Backend Setup**:
   ```bash
   cd backend
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -e ".[dev]"
   alembic upgrade head
   uvicorn app.main:app --reload --port 8000
   ```

4. **Frontend Setup**:
   ```bash
   cd ../frontend
   npm install
   npm run dev
   ```
