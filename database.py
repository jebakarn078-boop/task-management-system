import os
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "tasks.db"
SCHEMA = BASE_DIR / "schema.sql"
SQLITE_SCHEMA = BASE_DIR / "schema.sqlite.sql"


def _database_url():
    return os.environ.get("DATABASE_URL", "").strip()


def is_postgres():
    return bool(_database_url())


def _connect():
    url = _database_url()
    if url:
        if not url.startswith(("postgresql://", "postgres://")):
            raise RuntimeError(
                "DATABASE_URL must be a PostgreSQL connection URL."
            )
        import psycopg
        from psycopg.rows import dict_row

        if url.startswith("postgres://"):
            url = f"postgresql://{url[len('postgres://'):]}"
        return psycopg.connect(url, row_factory=dict_row)

    if os.environ.get("APP_ENV", "development").lower() == "production":
        raise RuntimeError(
            "DATABASE_URL is required in production. "
            "SQLite fallback is only available for local development."
        )

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


class DatabaseConnection:
    def __init__(self, connection, postgres):
        self.connection = connection
        self.postgres = postgres

    def _query(self, query):
        return re.sub(r"\?", "%s", query) if self.postgres else query

    def execute(self, query, parameters=()):
        return self.connection.execute(self._query(query), parameters)

    def executemany(self, query, parameters):
        return self.connection.executemany(self._query(query), parameters)

    def commit(self):
        self.connection.commit()

    def rollback(self):
        self.connection.rollback()


@contextmanager
def get_db():
    postgres = is_postgres()
    connection = _connect()
    try:
        yield DatabaseConnection(connection, postgres)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def is_integrity_error(error):
    if is_postgres():
        import psycopg

        return isinstance(error, psycopg.IntegrityError)
    return isinstance(error, sqlite3.IntegrityError)


def _initialize_schema(db, postgres):
    schema_file = SCHEMA if postgres else SQLITE_SCHEMA
    schema = schema_file.read_text(encoding="utf-8")
    for statement in schema.split(";"):
        if statement.strip():
            db.execute(statement)


def init_db():
    postgres = is_postgres()
    with get_db() as db:
        if postgres:
            db.execute("SELECT pg_advisory_xact_lock(?)", (721049261,))
        _initialize_schema(db, postgres)

        if not postgres:
            blocklist_columns = {
                row["name"]
                for row in db.execute("PRAGMA table_info(token_blocklist)")
            }
            if "expires_at" not in blocklist_columns:
                db.execute(
                    "ALTER TABLE token_blocklist ADD COLUMN expires_at TEXT"
                )
                db.execute(
                    """
                    UPDATE token_blocklist
                    SET expires_at = datetime(created_at, '+1 day')
                    WHERE expires_at IS NULL
                    """
                )
            db.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_token_blocklist_expires_at
                ON token_blocklist(expires_at)
                """
            )

        db.execute(
            """
            DELETE FROM token_blocklist
            WHERE expires_at IS NULL OR expires_at <= CURRENT_TIMESTAMP
            """
        )

        employees_empty = (
            db.execute(
                "SELECT COUNT(*) AS count FROM Employees"
            ).fetchone()["count"] == 0
        )
        if employees_empty:
            db.executemany(
                """
                INSERT INTO Employees (name, email, department)
                VALUES (?, ?, ?)
                ON CONFLICT (email) DO NOTHING
                """,
                [
                    ("Ava Johnson", "ava.johnson@example.com", "Engineering"),
                    ("Liam Smith", "liam.smith@example.com", "Marketing"),
                    ("Noah Williams", "noah.williams@example.com", "Design"),
                    ("Emma Brown", "emma.brown@example.com", "Operations"),
                ],
            )

        if db.execute("SELECT COUNT(*) AS count FROM tasks").fetchone()["count"] == 0:
            db.executemany(
                """
                INSERT INTO tasks
                    (title, description, employee_id, status, priority, due_date)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    ("Finalize landing page", "Review the final responsive layout and publish it.", 1, "In Progress", "High", "2025-12-20"),
                    ("Prepare campaign brief", "Create the brief for the January product campaign.", 2, "Pending", "Medium", "2025-12-22"),
                    ("Update brand guidelines", "Add the new color palette and typography guidance.", 3, "Completed", "Low", "2025-12-15"),
                ],
            )


if __name__ == "__main__":
    init_db()
    print("Database initialized.")
