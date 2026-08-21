"""Unit tests for Flask web dashboard routes and API endpoints."""

import datetime
from pathlib import Path

import pytest

from supplyguard.models import Finding, RemediationAttempt, Scan, init_db
from supplyguard.web.app import create_app


@pytest.fixture
def app(tmp_path: Path):
    db_path = tmp_path / "test_web.db"
    _, session_factory = init_db(db_path)

    # Seed test scan
    with session_factory() as session:
        now = datetime.datetime.now(datetime.UTC)
        scan = Scan(
            project_path="/test/demo-repo",
            started_at=now,
            finished_at=now,
            risk_score=45,
            components_count=12,
            findings_count=3,
        )
        session.add(scan)
        session.flush()

        session.add(
            Finding(
                scan_id=scan.id,
                source="sast",
                severity="HIGH",
                file="app.py",
                line=10,
                rule_id="ai-sql-injection-concat",
                cwe="CWE-89",
                message="SQL injection query",
            )
        )
        session.add(
            RemediationAttempt(
                scan_id=scan.id,
                strategy="LLM_ASSISTED",
                iteration=1,
                outcome="RESOLVED",
                diff_text="--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-cursor.execute(f'...')\n+cursor.execute('...', (x,))",
                explanation="Parameterized query patch applied.",
            )
        )
        session.commit()

    flask_app = create_app(db_path=db_path)
    flask_app.config["TESTING"] = True
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()


def test_dashboard_index(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Security Dashboard" in response.data
    assert b"45 / 100" in response.data


def test_scan_detail_view(client):
    response = client.get("/scan/1")
    assert response.status_code == 200
    assert b"Scan #1 Report" in response.data
    assert b"ai-sql-injection-concat" in response.data


def test_scan_detail_not_found(client):
    response = client.get("/scan/999")
    assert response.status_code == 404


def test_remediation_view(client):
    response = client.get("/scan/1/remediation")
    assert response.status_code == 200
    assert b"Remediation Audit Trail" in response.data
    assert b"Parameterized query patch applied." in response.data
    assert b"Iteration #1" in response.data


def test_api_scan_data(client):
    response = client.get("/api/scans/1")
    assert response.status_code == 200
    data = response.get_json()
    assert data["id"] == 1
    assert data["risk_score"] == 45
    assert data["severity_breakdown"]["HIGH"] >= 1
