"""Integration checks for transaction-scoped PostgreSQL session settings."""
import os

import psycopg
import pytest

from app.db import RLSContext, close_pool, transaction


@pytest.fixture(scope="module", autouse=True)
def prepare_database():
    dsn = os.getenv("DATABASE_URL")
    if not dsn:
        pytest.skip("PostgreSQL CI database is not configured")
    close_pool()
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("""
            DO $$
            BEGIN
              IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sultan_app') THEN
                CREATE ROLE sultan_app NOLOGIN NOSUPERUSER NOBYPASSRLS;
              END IF;
            END $$;
        """)
        conn.execute("GRANT sultan_app TO postgres")
        conn.execute("DROP TABLE IF EXISTS public.rls_context_test")
        conn.execute("CREATE TABLE public.rls_context_test (branch_id integer NOT NULL, payload text NOT NULL)")
        conn.execute("ALTER TABLE public.rls_context_test ENABLE ROW LEVEL SECURITY")
        conn.execute("""
            CREATE POLICY rls_context_test_policy ON public.rls_context_test
            TO sultan_app
            USING (branch_id = NULLIF(current_setting('sultan.branch_id', true), '')::integer)
            WITH CHECK (branch_id = NULLIF(current_setting('sultan.branch_id', true), '')::integer)
        """)
        conn.execute("GRANT SELECT, INSERT ON public.rls_context_test TO sultan_app")
        conn.execute("INSERT INTO public.rls_context_test VALUES (1,'one'),(2,'two')")
    yield
    close_pool()
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("DROP TABLE IF EXISTS public.rls_context_test")


def test_rls_filters_rows_by_branch():
    with transaction(RLSContext(user_id=11, branch_id=1)) as conn:
        rows = conn.execute("SELECT branch_id,payload FROM public.rls_context_test").fetchall()
    assert rows == [{"branch_id": 1, "payload": "one"}]


def test_rls_blocks_cross_branch_insert():
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with transaction(RLSContext(user_id=11, branch_id=1)) as conn:
            conn.execute("INSERT INTO public.rls_context_test VALUES (%s,%s)", (2, "blocked"))


def test_login_context_is_transaction_local():
    with transaction(RLSContext(login=True)) as conn:
        row = conn.execute("""
            SELECT current_setting('sultan.login',true) AS login,
                   current_setting('sultan.user_id',true) AS user_id,
                   current_setting('sultan.branch_id',true) AS branch_id
        """).fetchone()
    assert row == {"login": "true", "user_id": "", "branch_id": ""}
