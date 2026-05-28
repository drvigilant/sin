import pytest
from httpx import AsyncClient
from sin.api.server import app

@pytest.mark.asyncio
async def test_health_endpoint():
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "online"

@pytest.mark.asyncio
async def test_threats_endpoint():
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get("/threats", headers={"X-API-Key": "test"})
        assert response.status_code in [200, 401]

@pytest.mark.asyncio
async def test_devices_endpoint():
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get("/devices", headers={"X-API-Key": "test"})
        assert response.status_code in [200, 401]
