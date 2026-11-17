import pytest

from app.db import CompatRow, RLSContext, _translate_sql, postgres_connect


def test_sqlite_sql_translation_for_postgres():
    sql = _translate_sql(
        "SELECT * FROM users WHERE active=1 AND date(created_at)>=date(?) "
        "AND (? IS NULL OR branch_id=?)"
    )
    assert "active IS TRUE" in sql
    assert "NULLIF(created_at, '')::date>=(%s)::date" in sql
    assert "(%s::bigint IS NULL OR branch_id=%s)" in sql


def test_compat_row_supports_mapping_and_sqlite_indexing():
    row = CompatRow({"id": 7, "name": "product"})
    assert row["id"] == 7
    assert row[0] == 7
    assert list(row) == [7, "product"]
    assert dict(row) == {"id": 7, "name": "product"}


def test_postgres_connection_refuses_missing_request_context(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(RuntimeError, match="RLS context"):
        with postgres_connect():
            pass


def test_rls_flags_must_be_boolean():
    with pytest.raises(ValueError):
        RLSContext(user_id=1, is_owner="true").validate()
