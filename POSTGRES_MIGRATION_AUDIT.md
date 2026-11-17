# PostgreSQL migration audit

Target: Supabase project selected by the owner. Work branch: `supabase-postgres-migration`.

## Current application state

The current FastAPI application in `app/main.py` is SQLite-specific. It imports `sqlite3`, opens a local database file, enables SQLite PRAGMAs, initializes schema through `executescript`, and uses SQLite metadata via `PRAGMA table_info`.

The request layer uses qmark placeholders (`?`), SQLite row objects, `cursor.lastrowid`, and catches `sqlite3.Error` / `sqlite3.IntegrityError`. It also uses SQLite date expressions including `date(created_at)`, `date(?)`, and `date('now')`.

## Operations requiring a real PostgreSQL port

- Database connection lifecycle and transaction boundaries.
- Schema initialization and forward-only migrations (do not run SQLite DDL on PostgreSQL).
- Insert IDs: use explicit `INSERT ... RETURNING id` at each insert that consumes the generated ID.
- Boolean values: replace integer flags with Python booleans and PostgreSQL boolean predicates.
- Date filtering: use PostgreSQL casts / date comparisons with correctly typed parameters.
- Nullable filters: avoid ambiguous `? IS NULL` parameter inference; use explicit typed conditions or construct safe predicates.
- Integrity error handling: map psycopg constraint exceptions to existing HTTP responses.
- Row access: preserve mapping-style access used throughout the application.
- Transaction atomicity: sale, purchase, return, transfer approval, stock movement and cash-close writes must remain atomic.
- Concurrency: lock stock rows or use guarded updates to prevent overselling under concurrent requests.

## Backup and restore

The existing `/api/backup` and `/api/backup/restore` endpoints use SQLite's online backup API, SQLite integrity checks, database-file replacement, and WAL checkpointing. These endpoints cannot be carried over to PostgreSQL. Replace them with a controlled PostgreSQL dump/restore workflow (for example, server-side `pg_dump` / `pg_restore` with strict authorization, temporary-file handling, validation, and a recovery plan), or disable restore until that workflow is implemented. Never accept an uploaded SQLite file as a PostgreSQL restore.

## Deployment configuration

Current `requirements.txt` does not include a PostgreSQL driver. The Dockerfile and Render Blueprint still configure `SULTAN_DB_PATH=/data/sultan.db` and a persistent disk. These should only be removed after the application has been migrated and verified against PostgreSQL.

For Supabase connectivity, choose the connection endpoint based on Render's network reachability. Supabase documents direct connections as IPv6 by default and the shared session pooler as IPv4-capable; use SSL. Keep the connection string only in Render's server-side environment variables, never in frontend assets or source control.

## Verification required before merge or deployment

1. Run unit/integration tests against an isolated PostgreSQL database with the same schema.
2. Exercise login, permissions, branch filters, product CRUD, sale and stock decrement, purchase and stock increment, returns, transfers, debts, expenses, repairs, cash closing, reports, exports, and audit logging.
3. Verify transaction rollback on failures and concurrent stock changes.
4. Verify backup and restore using a disposable database and prove recovery before enabling restore in production.
5. Confirm health checks and startup do not mutate an existing production schema unexpectedly.

## Safety boundary

No production schema changes, data writes, Render deployments, or changes to the `main` branch are part of this audit. The application has not yet been ported; this document is an audit checklist, not a claim that PostgreSQL support is implemented.
