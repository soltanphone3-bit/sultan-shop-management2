# PostgreSQL migration foundation

## Current status

The legacy FastAPI routes still use SQLite. This commit adds a PostgreSQL
transaction boundary and validates the shape of the RLS actor context; it does
**not** switch production traffic to PostgreSQL.

## Required environment

- `DATABASE_URL`: PostgreSQL connection string stored only in the hosting
  provider's secret/environment settings.
- `DB_POOL_MIN` (optional, default 1)
- `DB_POOL_MAX` (optional, default 8)

The database login used by the DSN must be permitted to assume the existing
`sultan_app` role. Do not use a BYPASSRLS/superuser login for application
requests.

## RLS transaction contract

Every migrated request must use `transaction(RLSContext(...))`. The module
sets `SET LOCAL ROLE sultan_app` and all four `sultan.*` settings inside the
same transaction. Settings are transaction-local to prevent pooled-connection
context leakage.

Login lookups must use `RLSContext(login=True)` only. Authenticated branch
users must provide both `user_id` and `branch_id`. Owners must provide
`user_id` and `is_owner=True`.

## Not yet migrated

- Existing SQLite SQL, placeholders, generated-ID handling, and exception
  handling in `app/main.py`.
- SQLite schema initialization and file-based backup/restore endpoints.
- End-to-end tests for login, branch isolation, sales, stock concurrency,
  transfers, returns, debt payments, and cash closing.
- Render service configuration and production secrets.

Do not set production `DATABASE_URL` until all routes have been migrated and
PostgreSQL integration tests pass. No live Supabase schema changes are needed
for this foundation commit.
