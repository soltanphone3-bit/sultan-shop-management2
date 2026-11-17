#!/usr/bin/env python3
"""One-time, fail-closed migration from a local SULTAN SQLite file to Supabase PostgreSQL.

Default mode is a dry run. Execution requires CONFIRM_SQLITE_MIGRATION=YES and a
privileged MIGRATION_DATABASE_URL. The application DATABASE_URL must never be used
for this operation.
"""
from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path

import psycopg
from psycopg import sql


TABLES = [
    "branches", "users", "products", "stock", "sales", "sale_items", "expenses",
    "debts", "debt_payments", "repairs", "audit", "stock_movements", "purchases",
    "purchase_items", "returns", "transfers", "cash_closings", "login_attempts",
]
BOOLEAN_COLUMNS = {("branches", "active"), ("users", "active"), ("products", "active")}
DEFAULTS = {
    ("users", "permissions"): "",
    ("users", "session_version"): 0,
}
BATCH_SIZE = 1000


def fail(message: str) -> None:
    raise SystemExit(message)


def sqlite_table_columns(source: sqlite3.Connection, table: str) -> list[str]:
    return [row["name"] for row in source.execute(f'PRAGMA table_info("{table}")')]


def postgres_columns(target: psycopg.Connection) -> dict[str, list[str]]:
    rows = target.execute(
        """
        SELECT table_name, column_name
        FROM information_schema.columns
        WHERE table_schema='public' AND table_name = ANY(%s)
        ORDER BY table_name, ordinal_position
        """,
        (TABLES,),
    ).fetchall()
    result: dict[str, list[str]] = {name: [] for name in TABLES}
    for row in rows:
        result[row["table_name"]].append(row["column_name"])
    return result


def source_product_costs(source: sqlite3.Connection) -> dict[int, float]:
    if "products" not in {r["name"] for r in source.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )}:
        return {}
    cols = set(sqlite_table_columns(source, "products"))
    if not {"id", "purchase_price"}.issubset(cols):
        return {}
    return {
        int(row["id"]): float(row["purchase_price"] or 0)
        for row in source.execute("SELECT id,purchase_price FROM products")
    }


def value_for(table: str, column: str, row: dict, product_costs: dict[int, float]):
    if column in row:
        value = row[column]
    elif (table, column) in DEFAULTS:
        value = DEFAULTS[(table, column)]
    elif table == "sale_items" and column == "unit_cost":
        value = product_costs.get(int(row["product_id"]), 0.0)
    else:
        raise RuntimeError(f"SQLite table {table} is missing required PostgreSQL column {column}")
    if (table, column) in BOOLEAN_COLUMNS and value is not None:
        return bool(value)
    return value


def run() -> None:
    sqlite_path = Path(os.getenv("SQLITE_DB_PATH", "")).expanduser()
    dsn = os.getenv("MIGRATION_DATABASE_URL", "").strip()
    if not sqlite_path.is_file():
        fail("Set SQLITE_DB_PATH to an existing SQLite database file.")
    if not dsn:
        fail("Set MIGRATION_DATABASE_URL to a privileged Supabase PostgreSQL connection string.")
    if os.getenv("DATABASE_URL"):
        fail("Unset DATABASE_URL while migrating; use MIGRATION_DATABASE_URL only.")

    with sqlite3.connect(f"file:{sqlite_path}?mode=ro", uri=True) as source:
        source.row_factory = sqlite3.Row
        source.execute("PRAGMA foreign_keys=ON")
        fk_errors = source.execute("PRAGMA foreign_key_check").fetchall()
        if fk_errors:
            fail(f"SQLite foreign_key_check failed with {len(fk_errors)} violations.")

        source_tables = {r["name"] for r in source.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        missing_tables = sorted(set(TABLES) - source_tables)
        if missing_tables:
            fail("SQLite source is missing application tables: " + ", ".join(missing_tables))

        source_counts = {
            table: source.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
            for table in TABLES
        }
        product_costs = source_product_costs(source)

        with psycopg.connect(dsn, row_factory=psycopg.rows.dict_row) as target:
            role = target.execute(
                "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user"
            ).fetchone()
            if not role or not (role["rolsuper"] or role["rolbypassrls"]):
                fail("Migration connection must be a PostgreSQL superuser or BYPASSRLS role.")
            target_cols = postgres_columns(target)
            missing_target = [name for name in TABLES if not target_cols.get(name)]
            if missing_target:
                fail("Target PostgreSQL schema is missing tables: " + ", ".join(missing_target))

            for table in TABLES:
                src_cols = set(sqlite_table_columns(source, table))
                dst_cols = set(target_cols[table])
                extras = sorted(src_cols - dst_cols)
                if extras:
                    fail(f"SQLite table {table} has unmapped columns: {', '.join(extras)}")
                for column in dst_cols - src_cols:
                    if (table, column) not in DEFAULTS and not (table == "sale_items" and column == "unit_cost"):
                        fail(f"SQLite table {table} is missing PostgreSQL column {column}")

            target_counts = {
                table: target.execute(
                    sql.SQL("SELECT COUNT(*) AS n FROM {}.{}").format(
                        sql.Identifier("public"), sql.Identifier(table)
                    )
                ).fetchone()["n"]
                for table in TABLES
            }
            occupied = {table: n for table, n in target_counts.items() if n}
            if occupied:
                fail("Target tables are not empty; refusing to mix datasets: " + repr(occupied))

            print("Dry-run migration plan (no rows written):")
            for table in TABLES:
                print(f"  {table}: {source_counts[table]} rows")
            if os.getenv("CONFIRM_SQLITE_MIGRATION") != "YES":
                print("\nDry run only. To execute, set CONFIRM_SQLITE_MIGRATION=YES and run again.")
                return

            with target.transaction():
                for table in TABLES:
                    columns = target_cols[table]
                    insert = sql.SQL("INSERT INTO {}.{} ({}) VALUES ({})").format(
                        sql.Identifier("public"),
                        sql.Identifier(table),
                        sql.SQL(", ").join(map(sql.Identifier, columns)),
                        sql.SQL(", ").join(sql.Placeholder() for _ in columns),
                    )
                    cursor = source.execute(f'SELECT * FROM "{table}"')
                    while True:
                        batch = cursor.fetchmany(BATCH_SIZE)
                        if not batch:
                            break
                        values = [
                            tuple(value_for(table, column, dict(row), product_costs) for column in columns)
                            for row in batch
                        ]
                        target.cursor().executemany(insert, values)

                for table in TABLES:
                    if "id" not in target_cols[table]:
                        continue
                    sequence = target.execute(
                        "SELECT pg_get_serial_sequence(%s, 'id') AS sequence",
                        (f"public.{table}",),
                    ).fetchone()["sequence"]
                    if sequence:
                        max_id = target.execute(
                            sql.SQL("SELECT COALESCE(MAX(id),0) AS max_id FROM {}.{}").format(
                                sql.Identifier("public"), sql.Identifier(table)
                            )
                        ).fetchone()["max_id"]
                        if max_id:
                            target.execute("SELECT setval(%s::regclass, %s, true)", (sequence, max_id))

                for table in TABLES:
                    actual = target.execute(
                        sql.SQL("SELECT COUNT(*) AS n FROM {}.{}").format(
                            sql.Identifier("public"), sql.Identifier(table)
                        )
                    ).fetchone()["n"]
                    if actual != source_counts[table]:
                        raise RuntimeError(
                            f"Row-count verification failed for {table}: "
                            f"source={source_counts[table]}, target={actual}"
                        )

            print("\nMigration completed and row counts verified for all 18 tables.")
            print("Historical sale_items.unit_cost values were estimated from each product's current purchase_price when absent in SQLite.")


if __name__ == "__main__":
    try:
        run()
    except Exception as exc:
        print(f"Migration aborted: {exc}", file=sys.stderr)
        raise
