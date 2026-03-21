# Module B (Flask + RBAC + Indexing)

This module implements a local Flask web app and API layer for SafeDocs, with:

- Session-authenticated APIs
- Admin vs Regular RBAC
- Member portfolio UI
- CRUD APIs for project tables (Documents)
- Permission grant/revoke APIs
- Security audit logging (table + local file)
- SQL indexing scripts and EXPLAIN profiling hooks

## Project Layout

- `module_B/app.py`: app entry point
- `module_B/__init__.py`: app factory + bootstrap
- `module_B/routes.py`: UI/API routes
- `module_B/auth.py`: auth/session validation decorators
- `module_B/models.py`: core module tables
- `module_B/database.py`: DB session and bootstrap helpers
- `module_B/audit.py`: audit file + table logging helpers
- `module_B/templates/`: UI templates
- `module_B/sql/create_core_tables.sql`: core table DDL
- `module_B/sql/indexes.sql`: indexing strategy DDL
- `module_B/benchmark.py`: query timing + EXPLAIN output
- `module_B/logs/audit.log`: local audit file

## Environment

Copy the values from `.env.example` into your local `.env` (root or module path), then set:

- `DB_USER`
- `DB_PASSWORD`
- `DB_HOST`
- `DB_PORT`
- `DB_NAME`
- `JWT_SECRET`
- `DEFAULT_ADMIN_USERNAME`
- `DEFAULT_ADMIN_PASSWORD`

## Install

From repository root:

```powershell
venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Run

From repository root:

```powershell
venv\Scripts\python.exe -m module_B.app
```

Open:

- `http://127.0.0.1:5000/login` (UI login)
- `http://127.0.0.1:5000/` (welcome API)

## Required Auth APIs

- `GET /api/health`: returns service health and DB availability status.
- `POST /login`
  - JSON: `{"user": "...", "password": "..."}`
- `GET /isAuth`
  - Header: `Authorization: Bearer <session_token>`
- `GET /`

## Additional APIs

- `POST /api/members`
- `DELETE /api/members/<core_user_id>`
- `GET /api/documents`
- `GET /api/documents/<doc_id>`
- `POST /api/documents`
- `PUT /api/documents/<doc_id>`
- `DELETE /api/documents/<doc_id>`
- `POST /api/permissions/grant`
- `POST /api/permissions/revoke`
- `GET /api/audit/logs`
- `GET /api/audit/unauthorized`
- `GET /api/optimization/explain/documents`

## SQL Optimization Workflow

1. Capture baseline query profile using `module_B/benchmark.py`
2. Apply indexes from `module_B/sql/indexes.sql`
3. Rerun benchmark and compare:
   - `average_ms`
   - EXPLAIN output

## Notes

- If MySQL is down, the app starts in degraded mode and DB-backed endpoints return a DB unavailable response.
- Project-specific tables from Task 1 are expected in the same database (for example: `Users`, `Documents`, `Permissions`, `Logs`).
