"""PostgreSQL transaction boundary with transaction-local Supabase RLS context.

This module is deliberately not wired into the legacy SQLite routes yet. Routes
must be migrated as a unit before DATABASE_URL is enabled in production.
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool


@dataclass(frozen=True)
class RLSContext:
    user_id: str | int | None = None
    branch_id: str | int | None = None
    is_owner: bool = False
    login: bool = False

    def validate(self) -> None:
        if self.login and (self.user_id is not None or self.branch_id is not None or self.is_owner):
            raise ValueError("Login context must not carry an authenticated actor")
        if not self.login and self.user_id is None:
            raise ValueError("Authenticated database context requires user_id")
        if self.user_id is not None:
            try:
                if int(self.user_id) <= 0:
                    raise ValueError()
            except (TypeError, ValueError):
                raise ValueError("user_id must be a positive integer")
        if self.branch_id is not None:
            try:
                if int(self.branch_id) <= 0:
                    raise ValueError()
            except (TypeError, ValueError):
                raise ValueError("branch_id must be a positive integer")
        if not self.login and not self.is_owner and self.branch_id is None:
            raise ValueError("Branch-scoped users require branch_id")


_pool: ConnectionPool | None = None


def _get_pool() -> ConnectionPool:
    global _pool
    dsn = os.getenv("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL is required for PostgreSQL mode")
    if _pool is None:
        _pool = ConnectionPool(
            conninfo=dsn,
            min_size=int(os.getenv("DB_POOL_MIN", "1")),
            max_size=int(os.getenv("DB_POOL_MAX", "8")),
            kwargs={"row_factory": dict_row},
            open=True,
        )
    return _pool


@contextmanager
def transaction(context: RLSContext) -> Iterator[Connection]:
    """Yield one transaction with role and RLS settings scoped to that transaction."""
    context.validate()
    with _get_pool().connection() as conn:
        with conn.transaction():
            # Fixed role name; never interpolate a caller-controlled identifier.
            conn.execute("SET LOCAL ROLE sultan_app")
            conn.execute(
                """
                SELECT
                  set_config('sultan.user_id', %s, true),
                  set_config('sultan.branch_id', %s, true),
                  set_config('sultan.is_owner', %s, true),
                  set_config('sultan.login', %s, true)
                """,
                (
                    "" if context.user_id is None else str(context.user_id),
                    "" if context.branch_id is None else str(context.branch_id),
                    "true" if context.is_owner else "false",
                    "true" if context.login else "false",
                ),
            )
            yield conn


def close_pool() -> None:
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None
