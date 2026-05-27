import pytest
from starlette.testclient import TestClient
from sin.api.server import app

def test_health_endpoint():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["api"] == "online"
