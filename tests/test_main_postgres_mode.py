"""Import-time smoke test for the production PostgreSQL application mode."""

import app.main as main


def test_postgres_mode_is_selected_from_database_url():
    assert main.POSTGRES_MODE is True
    assert callable(main.bootstrap_postgres)
    assert callable(main.startup_database)


def test_production_postgres_does_not_run_sqlite_schema_initializer():
    # Startup dispatch is explicit: Postgres bootstrap, not CREATE TABLE/SQLite seed.
    assert main.POSTGRES_MODE
    assert "init_db()" in main.startup_database.__code__.co_names
    assert "bootstrap_postgres" in main.startup_database.__code__.co_names
