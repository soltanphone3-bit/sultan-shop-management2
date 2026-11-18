"""PostgreSQL transaction boundary and compatibility adapter for the legacy routes.

Every PostgreSQL operation must run in a transaction with a validated, transaction-
local RLS context. The adapter preserves the small sqlite3 connection surface used
by the API while translating the SQL constructs that differ between SQLite/PG.
"""
from __future__ import annotations

import os
import re
import sqlite3
import threading
from contextvars import ContextVar
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator

import psycopg
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
        if not isinstance(self.is_owner, bool) or not isinstance(self.login, bool):
            raise ValueError("RLS flags must be booleans")
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
_pool_lock = threading.Lock()
_request_context: ContextVar[RLSContext | None] = ContextVar("sultan_rls_context", default=None)


def set_request_context(context: RLSContext) -> None:
    """Set the authenticated actor for the current ASGI request/task."""
    context.validate()
    _request_context.set(context)


def reset_request_context() -> None:
    _request_context.set(None)


def _get_pool() -> ConnectionPool:
    global _pool
    dsn = os.getenv("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL is required for PostgreSQL mode")
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                _pool = ConnectionPool(
                    conninfo=dsn,
                    min_size=int(os.getenv("DB_POOL_MIN", "1")),
                    max_size=int(os.getenv("DB_POOL_MAX", "8")),
                    kwargs={"row_factory": dict_row, "prepare_threshold": None, "connect_timeout": 10, "application_name": "sultan-shop-management"},
                    open=True,
                    timeout=10,
                    max_waiting=32,
                )
    return _pool


@contextmanager
def transaction(context: RLSContext) -> Iterator[Connection]:
    """Yield one transaction with role and RLS settings scoped to that transaction."""
    context.validate()
    with _get_pool().connection() as conn:
        with conn.transaction():
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


class CompatRow(dict):
    """Mapping row that also preserves sqlite3.Row-style numeric indexing/iteration."""
    def __getitem__(self, key):
        if isinstance(key, int):
            try:
                return tuple(self.values())[key]
            except IndexError:
                raise IndexError(key)
        return super().__getitem__(key)

    def __iter__(self):
        return iter(self.values())


class CompatCursor:
    def __init__(self, cursor, lastrowid=None):
        self._cursor = cursor
        self.lastrowid = lastrowid

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def fetchone(self):
        row = self._cursor.fetchone()
        return CompatRow(row) if row is not None else None

    def fetchall(self):
        return [CompatRow(row) for row in self._cursor.fetchall()]

    def __iter__(self):
        for row in self._cursor:
            yield CompatRow(row)


_ID_TABLES = {
    "branches", "users", "products", "stock", "sales", "sale_items", "expenses",
    "debts", "debt_payments", "repairs", "audit", "stock_movements", "purchases",
    "purchase_items", "returns", "transfers", "cash_closings",
}


def _translate_sql(sql: str) -> str:
    # This codebase uses positional ? parameters and has no literal question marks
    # in SQL strings. SQL values remain bound parameters, never interpolated.
    sql = sql.replace("?", "%s")
    sql = re.sub(r"\bactive\s*=\s*1\b", "active = TRUE", sql, flags=re.I)
    sql = re.sub(r"\bactive\s*=\s*0\b", "active = FALSE", sql, flags=re.I)
    sql = re.sub(r"date\(\s*'now'\s*\)", "CURRENT_DATE", sql, flags=re.I)
    sql = re.sub(r"date\(\s*(%s)\s*\)", r"(\1)::date", sql, flags=re.I)
    sql = re.sub(r"date\(\s*([a-zA-Z_][\w.]*?)\s*\)", r"NULLIF(\1, '')::date", sql, flags=re.I)
    sql = re.sub(r"\(%s\s+IS\s+NULL", "(%s::bigint IS NULL", sql, flags=re.I)
    sql = re.sub(r"(::date\s*(?:=|<=|>=|<|>)\s*)%s", r"\1%s::date", sql, flags=re.I)
    return sql


class CompatConnection:
    def __init__(self, connection: Connection):
        self._connection = connection

    def execute(self, sql: str, params=()):
        translated = _translate_sql(sql)
        lastrowid = None
        match = re.match(r"\s*INSERT\s+INTO\s+([a-zA-Z_][\w]*)", sql, flags=re.I)
        if match and match.group(1).lower() in _ID_TABLES and not re.search(r"\bRETURNING\b", sql, flags=re.I):
            translated += " RETURNING id"
            try:
                cur = self._connection.execute(translated, params or ())
                row = cur.fetchone()
                lastrowid = row["id"] if row else None
                return CompatCursor(cur, lastrowid)
            except psycopg.IntegrityError as exc:
                raise sqlite3.IntegrityError(str(exc)) from exc
            except psycopg.Error as exc:
                raise sqlite3.Error(str(exc)) from exc
        try:
            return CompatCursor(self._connection.execute(translated, params or ()), lastrowid)
        except psycopg.IntegrityError as exc:
            raise sqlite3.IntegrityError(str(exc)) from exc
        except psycopg.Error as exc:
            raise sqlite3.Error(str(exc)) from exc

    def executemany(self, sql: str, seq):
        try:
            return CompatCursor(self._connection.executemany(_translate_sql(sql), seq))
        except psycopg.IntegrityError as exc:
            raise sqlite3.IntegrityError(str(exc)) from exc
        except psycopg.Error as exc:
            raise sqlite3.Error(str(exc)) from exc


@contextmanager
def postgres_connect(context: RLSContext | None = None):
    """Connection-shaped facade used by app.main; no implicit privileged context."""
    selected = context or _request_context.get()
    if selected is None:
        raise RuntimeError("Database access attempted without an authenticated RLS context")
    with transaction(selected) as conn:
        yield CompatConnection(conn)


def close_pool() -> None:
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None
