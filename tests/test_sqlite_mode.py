"""Verify that local development still uses SQLite after the PostgreSQL migration."""

import os
import subprocess
import sys


def test_local_sqlite_startup_and_login(tmp_path):
    db_path = tmp_path / "local-test.db"
    env = os.environ.copy()
    env.pop("DATABASE_URL", None)
    env["APP_ENV"] = "development"
    env["SULTAN_DB_PATH"] = str(db_path)
    env.pop("SULTAN_INITIAL_ADMIN_PASSWORD", None)
    env.pop("SULTAN_SECRET_KEY", None)
    env["SULTAN_COOKIE_SECURE"] = "0"
    code = """
from fastapi.testclient import TestClient
from app.main import app, POSTGRES_MODE
assert POSTGRES_MODE is False
with TestClient(app) as client:
    assert client.get('/healthz').status_code == 200
    response = client.post('/api/login', json={'username': 'admin', 'password': 'ChangeMe123!'})
    assert response.status_code == 200, response.text
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert db_path.exists()
