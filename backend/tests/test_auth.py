import pytest
from httpx import AsyncClient

from app.models.models import User


@pytest.mark.asyncio
async def test_register_tenant(client: AsyncClient):
    response = await client.post(
        "/api/v1/auth/register-tenant",
        json={"name": "Acme Security", "slug": "acme-sec"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Acme Security"
    assert data["slug"] == "acme-sec"
    assert "id" in data


@pytest.mark.asyncio
async def test_user_login_and_me(client: AsyncClient, test_user: User):
    # Test valid login
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@cybercorp.org", "password": "SecretPassword123!"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    token = data["access_token"]

    # Test /me endpoint
    me_resp = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_resp.status_code == 200
    me_data = me_resp.json()
    assert me_data["email"] == "analyst@cybercorp.org"
    assert me_data["role"] == "SECURITY_ANALYST"


@pytest.mark.asyncio
async def test_invalid_login(client: AsyncClient, test_user: User):
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@cybercorp.org", "password": "WrongPassword!"},
    )
    assert response.status_code == 401
