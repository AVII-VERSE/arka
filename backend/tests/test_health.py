import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_healthz(client: AsyncClient):
    response = await client.get("/api/v1/healthz")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data
    assert "timestamp" in data


@pytest.mark.asyncio
async def test_readyz(client: AsyncClient):
    response = await client.get("/api/v1/readyz")
    assert response.status_code == 200
    assert response.json()["status"] == "ready"


@pytest.mark.asyncio
async def test_livez(client: AsyncClient):
    response = await client.get("/api/v1/livez")
    assert response.status_code == 200
    assert response.json()["status"] == "live"
