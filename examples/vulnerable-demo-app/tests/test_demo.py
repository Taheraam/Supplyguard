import sys
from pathlib import Path

import pytest

# Ensure demo app directory is in sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_home_route(client):
    res = client.get("/")
    assert res.status_code == 200
    assert res.get_json()["status"] == "running"


def test_admin_delete_route(client):
    res = client.delete("/admin/users/42/delete")
    assert res.status_code == 200
    assert res.get_json()["deleted"] == "42"
