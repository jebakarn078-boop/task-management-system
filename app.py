import json
import os
import re
from datetime import datetime
from pathlib import Path
from flask import Flask, jsonify, render_template, request
from database import get_db, init_db, is_integrity_error
from token_blocklist import (
    initialize_blocklist_store,
    is_token_revoked as token_is_revoked,
    revoke_tokens,
)
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import timedelta

from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_jwt,
    get_jwt_identity,
    jwt_required
)
from flask_jwt_extended.exceptions import JWTDecodeError, JWTExtendedException

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def configured_jwt_keys():
    secret = os.environ.get("JWT_SECRET_KEY", "").strip()
    if len(secret.encode("utf-8")) < 32:
        raise RuntimeError(
            "JWT_SECRET_KEY must be configured with at least 32 bytes. "
            "Set it in the environment or in the local .env file."
        )

    key_id = os.environ.get("JWT_KEY_ID", "current").strip()
    if not key_id:
        raise RuntimeError("JWT_KEY_ID must not be empty.")

    try:
        previous_keys = json.loads(
            os.environ.get("JWT_PREVIOUS_KEYS", "{}")
        )
    except json.JSONDecodeError as error:
        raise RuntimeError("JWT_PREVIOUS_KEYS must be a JSON object.") from error

    if not isinstance(previous_keys, dict):
        raise RuntimeError("JWT_PREVIOUS_KEYS must be a JSON object.")

    if key_id in previous_keys:
        raise RuntimeError("JWT_KEY_ID must not also appear in JWT_PREVIOUS_KEYS.")

    for previous_id, previous_secret in previous_keys.items():
        if not isinstance(previous_id, str) or not previous_id.strip():
            raise RuntimeError("Previous JWT key IDs must be non-empty strings.")
        if not isinstance(previous_secret, str) or len(previous_secret.encode("utf-8")) < 32:
            raise RuntimeError(
                f"Previous JWT key {previous_id!r} must contain at least 32 bytes."
            )

    return secret, key_id, previous_keys


app = Flask(__name__)

current_secret, current_key_id, previous_keys = configured_jwt_keys()
app.config["JWT_SECRET_KEY"] = current_secret
app.config["JWT_KEY_ID"] = current_key_id
app.config["JWT_PREVIOUS_KEYS"] = previous_keys
app.config["DEBUG"] = (
    os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true")
    and os.environ.get("APP_ENV", "development").lower() != "production"
)

app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=15)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=1)

jwt = JWTManager(app)


@jwt.decode_key_loader
def select_jwt_decode_key(jwt_header, jwt_payload):
    key_id = jwt_header.get("kid")
    if key_id is None:
        return app.config["JWT_SECRET_KEY"]

    if key_id == app.config["JWT_KEY_ID"]:
        return app.config["JWT_SECRET_KEY"]

    previous_secret = app.config["JWT_PREVIOUS_KEYS"].get(key_id)
    if previous_secret is None:
        raise JWTDecodeError("Unknown JWT signing key.")
    return previous_secret


@jwt.token_in_blocklist_loader
def is_token_revoked(jwt_header, jwt_payload):
    return token_is_revoked(jwt_payload["jti"])


@jwt.invalid_token_loader
def invalid_token(reason):
    """Return 401 for malformed or unverifiable JWTs so the frontend's
    existing 401 handling (try refresh, then clear session) kicks in."""
    return jsonify({"error": "Invalid or expired session token."}), 401


@jwt.expired_token_loader
def expired_token(jwt_header, jwt_payload):
    return jsonify({"error": "Session expired. Please log in again."}), 401


@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({"error": "Internal server error."}), 500


@app.after_request
def set_security_headers(response):
    """Add baseline browser security headers to every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    return response


def escape_like(value):
    """Escape LIKE wildcards so user input matches literally."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def task_row_date(value):
    """Normalize a stored due date (TEXT string, date, or datetime) to a date."""
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str):
        return datetime.strptime(value[:10], "%Y-%m-%d").date()
    if hasattr(value, "year"):
        return value
    return None


def employee_exists(db, employee_id):
    if employee_id is None:
        return True
    return (
        db.execute("SELECT 1 FROM Employees WHERE id = ?", (employee_id,)).fetchone()
        is not None
    )

def task_row(row):
    if not row:
        return None
    result = dict(row)
    for column in ("due_date", "created_at", "updated_at"):
        value = result.get(column)
        if hasattr(value, "isoformat"):
            result[column] = value.isoformat()
    return result

MAX_TITLE_LENGTH = 120
MAX_DESCRIPTION_LENGTH = 2000
MAX_USERNAME_LENGTH = 64
MIN_PASSWORD_LENGTH = 8
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
VALID_STATUSES = ("Pending", "In Progress", "Completed")
VALID_PRIORITIES = ("Low", "Medium", "High")


def validate_task(data, existing_due_date=None):
    """Return a list of validation errors for a task payload.

    When ``existing_due_date`` is provided (task updates), the
    due-date-not-in-the-past rule only applies if the due date is being
    changed, so older tasks stay editable.
    """
    errors = []

    title = data.get("title", "")
    if not isinstance(title, str) or not title.strip():
        errors.append("Title is required.")
    elif len(title.strip()) > MAX_TITLE_LENGTH:
        errors.append(f"Title must be at most {MAX_TITLE_LENGTH} characters.")

    description = data.get("description", "") or ""
    if not isinstance(description, str):
        errors.append("Description must be text.")
    elif len(description) > MAX_DESCRIPTION_LENGTH:
        errors.append(f"Description must be at most {MAX_DESCRIPTION_LENGTH} characters.")

    if data.get("status", "Pending") not in VALID_STATUSES:
        errors.append("Invalid status.")
    if data.get("priority", "Medium") not in VALID_PRIORITIES:
        errors.append("Invalid priority.")

    due_date = data.get("due_date")
    parsed_due_date = None
    if due_date is not None:
        if not isinstance(due_date, str) or not DATE_PATTERN.match(due_date):
            errors.append("Due date must use the YYYY-MM-DD format.")
        else:
            try:
                parsed_due_date = datetime.strptime(due_date, "%Y-%m-%d").date()
            except ValueError:
                errors.append("Due date is not a valid calendar date.")

        if parsed_due_date is not None:
            changing_due_date = (
                existing_due_date is None
                or task_row_date(existing_due_date) != parsed_due_date
            )
            if changing_due_date and parsed_due_date < datetime.now().date():
                errors.append("Due date cannot be before the task creation date.")

    employee_id = data.get("employee_id")
    if employee_id is not None:
        if isinstance(employee_id, bool) or not isinstance(employee_id, int):
            errors.append("employee_id must be an integer.")

    return errors

def admin_required():
    def decorator(fn):
        @wraps(fn)
        def decorated(*args, **kwargs):
            claims = get_jwt()

            if claims.get("role") != "Admin":
                return jsonify({"error": "Admin access required."}), 403

            return fn(*args, **kwargs)

        return decorated

    return decorator

@app.route("/")
def index():
    return render_template("index.html")

@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}

    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not username:
        return jsonify({"error": "Username is required."}), 400

    if not 3 <= len(username) <= MAX_USERNAME_LENGTH:
        return jsonify({
            "error": f"Username must be between 3 and {MAX_USERNAME_LENGTH} characters."
        }), 400

    if not USERNAME_PATTERN.match(username):
        return jsonify({
            "error": "Username may only contain letters, numbers, dots, dashes and underscores."
        }), 400

    if len(password) < MIN_PASSWORD_LENGTH:
        return jsonify({
            "error": f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        }), 400

    password_hash = generate_password_hash(password)

    try:
        with get_db() as db:
            cursor = db.execute(
                """
                INSERT INTO users (username, password_hash, role)
                VALUES (?, ?, ?)
                RETURNING id
                """,
                (username, password_hash, "Employee")
            )
            user_id = cursor.fetchone()["id"]

        return jsonify({
            "id": user_id,
            "username": username,
            "role": "Employee",
            "message": "User registered successfully."
        }), 201

    except Exception as error:
        if is_integrity_error(error):
            return jsonify({"error": "Username already exists."}), 409
        raise
    
@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}

    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not username or not password:
        return jsonify({
            "error": "Username and password are required."
        }), 400

    with get_db() as db:
        user = db.execute(
            """
            SELECT id, username, password_hash, role
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

    if not user:
        return jsonify({
            "error": "Invalid username or password."
        }), 401

    if not check_password_hash(
        user["password_hash"],
        password
    ):
        return jsonify({
            "error": "Invalid username or password."
        }), 401

    claims = {
        "username": user["username"],
        "role": user["role"]
    }
    token_headers = {"kid": app.config["JWT_KEY_ID"]}

    access_token = create_access_token(
        identity=str(user["id"]),
        additional_claims=claims,
        additional_headers=token_headers
    )

    refresh_token = create_refresh_token(
        identity=str(user["id"]),
        additional_claims=claims,
        additional_headers=token_headers
    )

    return jsonify({
        "message": "Login successful.",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user_id": user["id"],
        "username": user["username"],
        "role": user["role"]
    }), 200

@app.post("/api/refresh")
@jwt_required(refresh=True)
def refresh():
    user_id = get_jwt_identity()

    with get_db() as db:
        user = db.execute(
            """
            SELECT id, username, role
            FROM users
            WHERE id = ?
            """,
            (user_id,)
        ).fetchone()

    if not user:
        return jsonify({
            "error": "User not found."
        }), 401

    access_token = create_access_token(
        identity=str(user["id"]),
        additional_claims={
            "username": user["username"],
            "role": user["role"]
        },
        additional_headers={"kid": app.config["JWT_KEY_ID"]}
    )

    return jsonify({
        "access_token": access_token,
        "user_id": user["id"],
        "username": user["username"],
        "role": user["role"]
    }), 200

@app.post("/api/logout")
@jwt_required()
def api_logout():
    data = request.get_json(silent=True) or {}
    refresh_token = data.get("refresh_token")
    if not isinstance(refresh_token, str) or not refresh_token:
        return jsonify({"error": "A refresh token is required."}), 400

    try:
        refresh_claims = decode_token(refresh_token)
    except JWTExtendedException:
        return jsonify({"error": "Invalid refresh token."}), 400

    if (
        refresh_claims.get("type") != "refresh"
        or refresh_claims.get("sub") != get_jwt_identity()
    ):
        return jsonify({"error": "Invalid refresh token."}), 400

    revoked_tokens = (
        (get_jwt()["jti"], get_jwt()["exp"]),
        (refresh_claims["jti"], refresh_claims["exp"])
    )
    revoke_tokens(revoked_tokens)

    return jsonify({"message": "Logout successful."}), 200

@app.get("/api/employees")
@jwt_required()
def employees():
    with get_db() as db:
        rows = db.execute("SELECT id, name, email, department, role FROM Employees ORDER BY name").fetchall()
    return jsonify([dict(row) for row in rows])

@app.delete("/api/employees/<int:employee_id>")
@jwt_required()
@admin_required()
def delete_employee(employee_id):
    with get_db() as db:
        cursor = db.execute(
            "DELETE FROM Employees WHERE id = ?",
            (employee_id,)
        )
    if cursor.rowcount == 0:
        return jsonify({"error": "Employee not found."}), 404
    return jsonify({"message": "Employee deleted."}), 200

@app.put("/api/employees/<int:employee_id>")
@jwt_required()
@admin_required()
def update_employee(employee_id):
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    if not name:
        return jsonify({"error": "Name is required."}), 400
    with get_db() as db:
        row = db.execute("SELECT id FROM Employees WHERE id = ?", (employee_id,)).fetchone()
        if not row:
            return jsonify({"error": "Employee not found."}), 404
        db.execute("UPDATE Employees SET name = ? WHERE id = ?", (name, employee_id))
        db.commit()
        updated = db.execute("SELECT id, name, email, department, role FROM Employees WHERE id = ?", (employee_id,)).fetchone()
    return jsonify(dict(updated))

@app.get("/api/tasks")
@jwt_required()
def list_tasks():
    status = request.args.get("status") or None
    employee_id = request.args.get("employee_id") or None
    if employee_id is not None:
        try:
            employee_id = int(employee_id)
        except ValueError:
            employee_id = -1
    search = request.args.get("search") or None
    search_pattern = f"%{escape_like(search)}%" if search is not None else None
    query = """
        SELECT
            t.id, t.title, t.description, t.employee_id, t.status,
            t.priority, t.due_date, t.created_at, t.updated_at,
            e.name AS employee_name
        FROM tasks t
        LEFT JOIN Employees e ON e.id = t.employee_id
        WHERE (CAST(? AS TEXT) IS NULL OR t.status = ?)
          AND (CAST(? AS INTEGER) IS NULL OR t.employee_id = ?)
          AND (
              CAST(? AS TEXT) IS NULL
              OR t.title LIKE ? ESCAPE '\\'
              OR t.description LIKE ? ESCAPE '\\'
          )
        ORDER BY
            CASE t.status
                WHEN 'In Progress' THEN 1
                WHEN 'Pending' THEN 2
                ELSE 3
            END,
            t.due_date IS NULL,
            t.due_date
    """
    params = (
        status, status,
        employee_id, employee_id,
        search, search_pattern, search_pattern
    )
    with get_db() as db:
        rows = db.execute(query, params).fetchall()
    return jsonify([task_row(row) for row in rows])

@app.get("/api/tasks/<int:task_id>")
@jwt_required()
def get_task(task_id):
    with get_db() as db:
        row = db.execute(
            """
            SELECT
                t.id, t.title, t.description, t.employee_id, t.status,
                t.priority, t.due_date, t.created_at, t.updated_at,
                e.name AS employee_name
            FROM tasks t
            LEFT JOIN Employees e ON e.id = t.employee_id
            WHERE t.id = ?
            """,
            (task_id,)
        ).fetchone()
    if not row: return jsonify({"error": "Task not found."}), 404
    return jsonify(task_row(row))

@app.post("/api/tasks")
@jwt_required()
@admin_required()
def create_task():
    data = request.get_json(silent=True) or {}
    errors = validate_task(data)
    if errors: return jsonify({"errors": errors}), 400
    with get_db() as db:
        if not employee_exists(db, data.get("employee_id")):
            return jsonify({"error": "Assigned employee not found."}), 400
        row = db.execute(
            """
            INSERT INTO tasks
                (title, description, employee_id, status, priority, due_date)
            VALUES (?, ?, ?, ?, ?, ?)
            RETURNING id
            """,
            (
                data["title"].strip(),
                (data.get("description") or "").strip(),
                data.get("employee_id") or None,
                data.get("status", "Pending"),
                data.get("priority", "Medium"),
                data.get("due_date") or None
            )
        ).fetchone()
    return jsonify({"id": row["id"], "message": "Task created."}), 201

@app.put("/api/tasks/<int:task_id>")
@jwt_required()
@admin_required()
def update_task(task_id):
    data = request.get_json(silent=True) or {}
    with get_db() as db:
        task = db.execute("SELECT id, due_date FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if not task: return jsonify({"error": "Task not found."}), 404
        errors = validate_task(data, existing_due_date=task["due_date"])
        if errors: return jsonify({"errors": errors}), 400
        if not employee_exists(db, data.get("employee_id")):
            return jsonify({"error": "Assigned employee not found."}), 400
        db.execute("UPDATE tasks SET title=?, description=?, employee_id=?, status=?, priority=?, due_date=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", (data["title"].strip(), (data.get("description") or "").strip(), data.get("employee_id") or None, data.get("status", "Pending"), data.get("priority", "Medium"), data.get("due_date") or None, task_id))
        db.commit()
    return jsonify({"message": "Task updated."})

@app.patch("/api/tasks/<int:task_id>/status")
@jwt_required()
def update_status(task_id):
    data = request.get_json(silent=True) or {}
    status = data.get("status")
    if status not in ("Pending", "In Progress", "Completed"): return jsonify({"error": "Invalid status."}), 400
    with get_db() as db:
        cursor = db.execute("UPDATE tasks SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", (status, task_id)); db.commit()
    if cursor.rowcount == 0: return jsonify({"error": "Task not found."}), 404
    return jsonify({"message": "Status updated."})

@app.delete("/api/tasks/<int:task_id>")
@jwt_required()
@admin_required()
def delete_task(task_id):
    with get_db() as db:
        task = db.execute(
            "SELECT id FROM tasks WHERE id = ?",
            (task_id,)
        ).fetchone()
        if not task:
            return jsonify({"error": "Task not found."}), 404

        cursor = db.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
        if cursor.rowcount == 0:
            return jsonify({"error": "Task not found."}), 404
    return jsonify({"message": "Task deleted."})

@app.get("/api/stats")
@jwt_required()
def stats():
    with get_db() as db:
        result = db.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN status = ? THEN 1 ELSE 0 END) AS pending,
                SUM(CASE WHEN status = ? THEN 1 ELSE 0 END) AS in_progress,
                SUM(CASE WHEN status = ? THEN 1 ELSE 0 END) AS completed
            FROM tasks
            """,
            ("Pending", "In Progress", "Completed")
        ).fetchone()
    return jsonify(dict(result))

if __name__ == "__main__":
    init_db()
    initialize_blocklist_store()
    app.run(debug=app.config["DEBUG"])
