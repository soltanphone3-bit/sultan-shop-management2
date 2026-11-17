"""Import-time smoke test for the production PostgreSQL application mode."""

import app.main as main


def test_postgres_mode_is_selected_from_database_url():
    assert main.POSTGRES_MODE is True
    assert callable(main.bootstrap_postgres)
    assert callable(main.startup_database)


def test_postgres_startup_runs_bootstrap_not_sqlite_initializer(monkeypatch):
    calls = []
    monkeypatch.setattr(main, "validate_postgres_schema", lambda: calls.append("validate"))
    monkeypatch.setattr(main, "bootstrap_postgres", lambda: calls.append("postgres"))
    monkeypatch.setattr(main, "init_db", lambda: calls.append("sqlite"))
    main.startup_database()
    assert calls == ["validate", "postgres"]
