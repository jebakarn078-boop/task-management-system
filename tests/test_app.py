import importlib
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault(
    "JWT_SECRET_KEY",
    "test-only-secret-key-that-is-at-least-32-bytes-long"
)

import app as task_app
import database
import token_blocklist
from werkzeug.security import generate_password_hash


class FakeCursor:
    def __init__(self, row=None):
        self.row = row

    def fetchone(self):
        return self.row


class FakePostgresConnection:
    def __init__(self):
        self.executed = []
        self.executed_many = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def execute(self, query, params=None):
        self.executed.append((query, params))
        return FakeCursor((1,) if query.lstrip().startswith("SELECT 1") else None)

    def executemany(self, query, params):
        self.executed_many.append((query, list(params)))


class TaskFlowApiTests(unittest.TestCase):
    def setUp(self):
        self.blocklist_url_patch = patch.dict(
            os.environ,
            {"DATABASE_URL": ""}
        )
        self.blocklist_url_patch.start()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_database = database.DATABASE
        database.DATABASE = Path(self.temp_dir.name) / "test.db"
        database.init_db()

        with database.get_db() as db:
            db.execute(
                """
                INSERT INTO users (username, password_hash, role)
                VALUES (?, ?, ?)
                """,
                ("admin-test", generate_password_hash("admin-password"), "Admin")
            )
            db.execute(
                """
                INSERT INTO users (username, password_hash, role)
                VALUES (?, ?, ?)
                """,
                ("employee-test", generate_password_hash("employee-password"), "Employee")
            )

        self.previous_testing = task_app.app.testing
        task_app.app.testing = True
        self.client = task_app.app.test_client()

    def tearDown(self):
        task_app.app.testing = self.previous_testing
        database.DATABASE = self.original_database
        self.temp_dir.cleanup()
        self.blocklist_url_patch.stop()

    def login(self, username="admin-test", password="admin-password"):
        response = self.client.post(
            "/api/login",
            json={"username": username, "password": password}
        )
        self.assertEqual(response.status_code, 200)
        return response.get_json()

    @staticmethod
    def auth(token):
        return {"Authorization": f"Bearer {token}"}

    def test_jwt_secret_requires_strong_environment_value(self):
        with patch.dict(
            os.environ,
            {"JWT_SECRET_KEY": "a" * 32},
            clear=True
        ):
            secret, key_id, previous = task_app.configured_jwt_keys()
            self.assertEqual(secret, "a" * 32)
            self.assertEqual(key_id, "current")
            self.assertEqual(previous, {})

        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "JWT_SECRET_KEY"):
                task_app.configured_jwt_keys()

        with patch.dict(os.environ, {"JWT_SECRET_KEY": "short"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "at least 32 bytes"):
                task_app.configured_jwt_keys()

    def test_jwt_secret_rotation_accepts_configured_previous_key(self):
        old_secret = "previous-test-secret-key-that-is-at-least-32-bytes"
        new_secret = "replacement-test-secret-key-that-is-at-least-32-bytes"
        old_key_id = task_app.app.config["JWT_KEY_ID"]
        old_config_secret = task_app.app.config["JWT_SECRET_KEY"]
        old_previous = task_app.app.config["JWT_PREVIOUS_KEYS"]
        try:
            task_app.app.config["JWT_SECRET_KEY"] = old_secret
            task_app.app.config["JWT_KEY_ID"] = "previous-test-key"
            with task_app.app.app_context():
                old_token = task_app.create_access_token(
                    identity="1",
                    additional_claims={"username": "admin-test", "role": "Admin"},
                    additional_headers={"kid": "previous-test-key"}
                )

            task_app.app.config["JWT_SECRET_KEY"] = new_secret
            task_app.app.config["JWT_KEY_ID"] = "replacement-test-key"
            task_app.app.config["JWT_PREVIOUS_KEYS"] = {
                "previous-test-key": old_secret
            }

            response = self.client.get(
                "/api/employees",
                headers=self.auth(old_token)
            )
            self.assertEqual(response.status_code, 200)
        finally:
            task_app.app.config["JWT_SECRET_KEY"] = old_config_secret
            task_app.app.config["JWT_KEY_ID"] = old_key_id
            task_app.app.config["JWT_PREVIOUS_KEYS"] = old_previous

    def test_expired_blocklist_entries_are_pruned_during_store_initialization(self):
        with database.get_db() as db:
            db.execute(
                """
                INSERT INTO token_blocklist (jti, expires_at)
                VALUES (?, datetime('now', '-1 day'))
                """,
                ("expired-test-token",)
            )

        token_blocklist.initialize_blocklist_store()

        with database.get_db() as db:
            expired = db.execute(
                "SELECT 1 FROM token_blocklist WHERE jti = ?",
                ("expired-test-token",)
            ).fetchone()
        self.assertIsNone(expired)

    def test_database_init_migrates_and_cleans_legacy_blocklist(self):
        with database.get_db() as db:
            db.execute("DROP TABLE token_blocklist")
            db.execute(
                """
                CREATE TABLE token_blocklist (
                    jti TEXT PRIMARY KEY NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            db.execute(
                """
                INSERT INTO token_blocklist (jti, created_at)
                VALUES (?, datetime('now', '-2 days'))
                """,
                ("legacy-revoked-token",)
            )

        database.init_db()

        with database.get_db() as db:
            columns = {
                row["name"]
                for row in db.execute("PRAGMA table_info(token_blocklist)")
            }
            legacy = db.execute(
                "SELECT 1 FROM token_blocklist WHERE jti = ?",
                ("legacy-revoked-token",)
            ).fetchone()

        self.assertIn("expires_at", columns)
        self.assertIsNone(legacy)

    def test_wsgi_entrypoint_initializes_database(self):
        wsgi_path = Path(__file__).resolve().parents[1] / "wsgi.py"
        spec = importlib.util.spec_from_file_location(
            "taskflow_test_wsgi",
            wsgi_path
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with database.get_db() as db:
            tables = {
                row["name"]
                for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
        self.assertIn("tasks", tables)
        self.assertIn("token_blocklist", tables)

    def test_postgres_adapter_parameterizes_shared_blocklist_queries(self):
        connection = FakePostgresConnection()

        class FakeDatabaseContext:
            def __enter__(self):
                return database.DatabaseConnection(connection, True)

            def __exit__(self, exc_type, exc_value, traceback):
                return False

        with (
            patch.object(
                token_blocklist,
                "get_db",
                side_effect=FakeDatabaseContext
            ),
            patch.object(
                token_blocklist,
                "is_postgres",
                return_value=True
            )
        ):
            token_blocklist.initialize_blocklist_store()
            self.assertTrue(token_blocklist.is_token_revoked("revoked-jti"))
            token_blocklist.revoke_tokens(
                [("revoked-jti", 1_798_000_000)]
            )

        self.assertIn(
            "SELECT 1 FROM token_blocklist WHERE jti = %s",
            connection.executed[1][0]
        )
        insert_query, inserted = connection.executed_many[0]
        self.assertIn("ON CONFLICT (jti) DO NOTHING", insert_query)
        self.assertEqual(inserted[0][0], "revoked-jti")
        self.assertIsInstance(inserted[0][1], datetime)

    def test_logout_revokes_access_and_refresh_tokens(self):
        tokens = self.login()
        response = self.client.post(
            "/api/logout",
            headers=self.auth(tokens["access_token"]),
            json={"refresh_token": tokens["refresh_token"]}
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["message"], "Logout successful.")
        self.assertEqual(
            self.client.get(
                "/api/employees",
                headers=self.auth(tokens["access_token"])
            ).status_code,
            401
        )
        self.assertEqual(
            self.client.get(
                "/api/tasks",
                headers=self.auth(tokens["access_token"])
            ).status_code,
            401
        )
        self.assertEqual(
            self.client.get(
                "/api/stats",
                headers=self.auth(tokens["access_token"])
            ).status_code,
            401
        )
        self.assertEqual(
            self.client.post(
                "/api/refresh",
                headers=self.auth(tokens["refresh_token"])
            ).status_code,
            401
        )

    def test_logout_rejects_refresh_token_from_another_user(self):
        admin_tokens = self.login()
        employee_tokens = self.login("employee-test", "employee-password")

        response = self.client.post(
            "/api/logout",
            headers=self.auth(admin_tokens["access_token"]),
            json={"refresh_token": employee_tokens["refresh_token"]}
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            self.client.get(
                "/api/employees",
                headers=self.auth(admin_tokens["access_token"])
            ).status_code,
            200
        )

    def test_existing_authenticated_apis_still_work(self):
        tokens = self.login()
        headers = self.auth(tokens["access_token"])

        self.assertEqual(self.client.get("/api/employees", headers=headers).status_code, 200)
        self.assertEqual(self.client.get("/api/tasks", headers=headers).status_code, 200)
        self.assertEqual(self.client.get("/api/stats", headers=headers).status_code, 200)

    def test_admin_can_create_task_but_employee_cannot(self):
        admin = self.login()
        created = self.client.post(
            "/api/tasks",
            headers=self.auth(admin["access_token"]),
            json={
                "title": "Shared database task",
                "description": "Created by an administrator",
                "status": "Pending",
                "priority": "Medium"
            }
        )
        self.assertEqual(created.status_code, 201)
        task_id = created.get_json()["id"]

        employee = self.login("employee-test", "employee-password")
        denied = self.client.post(
            "/api/tasks",
            headers=self.auth(employee["access_token"]),
            json={"title": "Should not be created"}
        )
        self.assertEqual(denied.status_code, 403)

        visible = self.client.get(
            f"/api/tasks/{task_id}",
            headers=self.auth(admin["access_token"])
        )
        self.assertEqual(visible.status_code, 200)
        self.assertEqual(visible.get_json()["title"], "Shared database task")

    def test_employee_can_update_task_status(self):
        employee = self.login("employee-test", "employee-password")
        response = self.client.patch(
            "/api/tasks/1/status",
            headers=self.auth(employee["access_token"]),
            json={"status": "In Progress"}
        )
        self.assertEqual(response.status_code, 200)

        with database.get_db() as db:
            row = db.execute(
                "SELECT status FROM tasks WHERE id = ?",
                (1,)
            ).fetchone()
        self.assertEqual(row["status"], "In Progress")

    def test_deleting_employee_unassigns_tasks(self):
        admin = self.login()
        response = self.client.delete(
            "/api/employees/1",
            headers=self.auth(admin["access_token"])
        )
        self.assertEqual(response.status_code, 200)

        with database.get_db() as db:
            row = db.execute(
                "SELECT employee_id FROM tasks WHERE id = ?",
                (1,)
            ).fetchone()
        self.assertIsNone(row["employee_id"])

    def test_task_schema_keeps_status_priority_checks_and_indexes(self):
        with database.get_db() as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute(
                    """
                    INSERT INTO tasks (title, status, priority)
                    VALUES (?, ?, ?)
                    """,
                    ("Invalid status", "Blocked", "Low")
                )
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute(
                    """
                    INSERT INTO tasks (title, status, priority)
                    VALUES (?, ?, ?)
                    """,
                    ("Invalid priority", "Pending", "Urgent")
                )

            indexes = {
                row["name"]
                for row in db.execute("PRAGMA index_list(tasks)")
            }

        self.assertIn("idx_tasks_status", indexes)
        self.assertIn("idx_tasks_employee_id", indexes)

    def test_production_requires_postgres_database_url(self):
        with patch.dict(
            os.environ,
            {"APP_ENV": "production", "DATABASE_URL": ""},
            clear=False
        ):
            with self.assertRaisesRegex(RuntimeError, "DATABASE_URL is required"):
                database._connect()

    def test_postgres_connection_adapter_uses_parameterized_placeholders(self):
        connection = FakePostgresConnection()
        adapter = database.DatabaseConnection(connection, True)
        adapter.execute("SELECT id FROM users WHERE username = ?", ("staff",))
        self.assertEqual(
            connection.executed[0],
            ("SELECT id FROM users WHERE username = %s", ("staff",))
        )

    def test_delete_requires_authentication_and_admin_role(self):
        no_auth = self.client.delete("/api/tasks/1")
        self.assertEqual(no_auth.status_code, 401)

        employee = self.login("employee-test", "employee-password")
        denied = self.client.delete(
            "/api/tasks/1",
            headers=self.auth(employee["access_token"])
        )
        self.assertEqual(denied.status_code, 403)

    def test_delete_returns_not_found_or_deletes_existing_task(self):
        admin = self.login()
        headers = self.auth(admin["access_token"])

        missing = self.client.delete("/api/tasks/9999", headers=headers)
        self.assertEqual(missing.status_code, 404)

        deleted = self.client.delete("/api/tasks/1", headers=headers)
        self.assertEqual(deleted.status_code, 200)

        with database.get_db() as db:
            task = db.execute(
                "SELECT id FROM tasks WHERE id = ?",
                (1,)
            ).fetchone()
        self.assertIsNone(task)

    def test_frontend_confirms_deletion_and_waits_for_logout_success(self):
        frontend = (
            Path(__file__).resolve().parents[1]
            / "static"
            / "js"
            / "app.js"
        ).read_text(encoding="utf-8")
        delete_handler = frontend.split(
            "async function removeTask(id) {",
            1
        )[1].split(
            "/* =========================================================\n   CREATE / UPDATE TASK",
            1
        )[0]

        self.assertLess(
            delete_handler.index("if (!confirm('Delete this task?'))"),
            delete_handler.index("await api(")
        )
        self.assertIn("method: 'DELETE'", delete_handler)

        logout_handler = frontend.split(
            "async function logout() {",
            1
        )[1].split(
            "/* =========================================================\n   SCREEN AND USER UI",
            1
        )[0]
        self.assertLess(
            logout_handler.index("await api("),
            logout_handler.index("clearLogin();")
        )
        self.assertIn("Network error.", frontend)
        self.assertIn("500: 'The server encountered an error.", frontend)

    def test_api_internal_errors_return_json_500(self):
        tokens = self.login()
        with patch.object(
            task_app,
            "get_db",
            side_effect=sqlite3.OperationalError("database unavailable")
        ):
            task_app.app.testing = False
            with self.assertLogs(task_app.app.logger.name, level="ERROR"):
                response = self.client.delete(
                    "/api/tasks/1",
                    headers=self.auth(tokens["access_token"])
                )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.get_json(),
            {"error": "Internal server error."}
        )


if __name__ == "__main__":
    unittest.main()
