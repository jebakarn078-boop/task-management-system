# TaskFlow setup

## Local development

Install dependencies and configure a local JWT key:

```powershell
python -m pip install -r requirements.txt
if (-not (Test-Path .env)) {
    Copy-Item .env.example .env
    $secret = python -c "import secrets; print(secrets.token_urlsafe(48))"
    (Get-Content .env -Raw).Replace("JWT_SECRET_KEY=", "JWT_SECRET_KEY=$secret") |
        Set-Content .env -Encoding ascii
}
python app.py
```

When `DATABASE_URL` is unset, local development uses `tasks.db` (SQLite).
The SQLite schema is in `schema.sqlite.sql`.

## Shared PostgreSQL deployment

Set `APP_ENV=production`, `JWT_SECRET_KEY` to a unique secret of at least 32
bytes, and `DATABASE_URL` to the PostgreSQL connection string. The same
PostgreSQL database stores users, employees, tasks, and revoked JWT identifiers.
For example:

```powershell
$env:APP_ENV = "production"
$env:DATABASE_URL = "postgresql://user:password@db-host:5432/taskflow?sslmode=require"
$env:JWT_SECRET_KEY = "<strong-secret-at-least-32-bytes>"
python -m pip install -r requirements.txt
waitress-serve --listen=0.0.0.0:5000 wsgi:app
```

Run the same app configuration on each instance. `wsgi.py` initializes the
PostgreSQL schema and default seed records before serving traffic. The
PostgreSQL schema is in `schema.sql`.

The existing local `tasks.db` is not copied automatically to PostgreSQL. Back
up and migrate any existing users, employees, and tasks before switching a
deployment to `DATABASE_URL`; the local database remains unchanged.

## Tests

```powershell
python -m unittest discover -s tests -v
```
