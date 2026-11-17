# PostgreSQL route migration map

This is an implementation checklist based on the current `app/main.py` and the
live Supabase catalog for project `cmotrerzosybbhegyitw`. It is not a claim
that the routes have been migrated.

## Verified database contract

- Supabase PostgreSQL 17.11; all 18 public application tables have RLS enabled.
- Application policies target `sultan_app`, which is NOLOGIN and NOBYPASSRLS.
- The `postgres` role is BYPASSRLS and must not be used by application traffic.
- Policies read transaction-local settings: `sultan.user_id`,
  `sultan.branch_id`, `sultan.is_owner`, and `sultan.login`.
- Login reads on `users` and `login_attempts` require login context.
- Product reads are available to the application role; product writes require
  owner context. Other business tables are owner- or branch-scoped.
- Branch and actor foreign keys in Supabase are stricter than the old SQLite
  initializer. Preserve those constraints; do not weaken them to make inserts
  pass.

## Route groups and required context

| Route/helper group | Functions in `main.py` | Required database context |
|---|---|---|
| Startup and health | `init_db`, `healthz` | Remove SQLite initialization; health check uses a minimal PostgreSQL connection and does not bypass RLS for business data. |
| Authentication | `login`, `current_user`, `logout`, `me` | Login lookup and rate-limit read/write in one `RLSContext(login=True)` transaction. Authenticated user lookup must use actor context; token/session version check must remain effective. |
| User administration | `change_password`, `users`, `add_user`, `user_active`, `set_user_permissions`, `get_user_permissions` | Owner context for administration; actor context for password change. |
| Branches and products | `branches`, `add_branch`, `products`, `add_product`, `update_product`, `delete_product` | Owner or branch context. Product writes must remain owner-only in line with existing RLS policies. |
| Sales and stock | `create_sale`, `sales`, `sale_detail`, `create_return`, `returnable_items` | Actor/branch context; lock relevant stock rows during sale and return calculations; use `RETURNING id`. |
| Expenses and debts | `expenses`, `add_expense`, `debts`, `add_debt`, `debt_payment` | Actor/branch context; lock debt row before validating and applying a payment. |
| Repairs and dashboard | `repairs`, `add_repair`, `update_repair`, `dashboard`, `reports`, `notifications` | Actor/branch context; retain branch filters as defense in depth in addition to RLS. |
| Audit and reports | `audit`, `audit_log`, `report_summary`, `export_report_csv`, `export_report_xlsx`, `calculate_zakat` | Actor context; owner context for global audit and owner-only calculations. |
| Purchases and movements | `create_purchase`, `list_purchases`, `stock_movements`, `stocktake_adjust` | Actor/branch context; row locks/upserts for stock mutations. |
| Inter-branch transfers | `request_transfer`, `list_transfers`, `decide_transfer` | Actor context for requests; owner context for decisions; lock transfer and source stock rows before approval. |
| Cash closing | `create_cash_closing`, `list_cash_closings` | Actor/branch context; preserve unique `(branch_id,business_date)` conflict behavior. |
| Backup and restore | `backup`, `restore_backup` | Replace SQLite file operations with controlled PostgreSQL dump/restore workflow, or disable these endpoints until a safe operator-only process exists. |

## SQL portability work still required

- Replace SQLite `?` placeholders with psycopg `%s` placeholders.
- Replace every `cursor.lastrowid` with explicit `INSERT ... RETURNING id`.
- Replace SQLite `date(column)` and `date('now')` expressions with
  PostgreSQL-compatible casts/date expressions, preserving text-date semantics.
- Convert boolean writes and predicates from integer `1/0` to PostgreSQL
  booleans for `branches.active`, `products.active`, and `users.active`.
- Replace `sqlite3.IntegrityError` handling with psycopg exception classes and
  inspect constraint names where the API distinguishes duplicate/foreign-key
  failures.
- Replace `executescript` and PRAGMA schema inspection with versioned,
  reproducible migrations. Do not initialize or seed production Supabase from
  application startup.
- Keep each multi-statement business operation inside one
  `transaction(RLSContext(...))` block. Do not open a second connection inside
  a transaction to perform branch checks or audit writes.

## Required automated acceptance tests

Run against an ephemeral PostgreSQL 17 service in CI, never against production:

1. Login success/failure, rate-limit upsert, session version invalidation.
2. Branch A cannot read or mutate Branch B rows; owner can access both.
3. Sales decrement stock atomically and reject concurrent overselling.
4. Purchases, returns, transfers, and stocktake preserve stock invariants.
5. Debt payments cannot overpay under concurrent requests.
6. Cash closing enforces one close per branch/business date.
7. Pool reuse does not retain a previous request's RLS settings.
8. All business writes preserve the live schema's foreign keys and RLS policies.

## Deployment gate

Do not enable `DATABASE_URL`, merge this branch, or deploy until the route
migration is complete and the PostgreSQL 17 integration suite passes. Keep the
existing Render static-site service untouched; it is not this FastAPI app.
