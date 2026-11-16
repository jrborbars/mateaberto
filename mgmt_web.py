"""Management Web Server — sole writer of user identity data.

Detached from doorlock control. Runs behind self-signed TLS on localhost.
Only this service may INSERT/UPDATE/DELETE on the `users` table.
"""

import asyncio
import hmac
import logging
import os
import sqlite3
import sys
import time
from contextlib import contextmanager

from argon2 import PasswordHasher
from dotenv import load_dotenv
from quart import Quart, request, jsonify

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
load_dotenv()

MGMT_HOST = os.getenv("MGMT_HOST", "127.0.0.1")
MGMT_PORT = int(os.getenv("MGMT_PORT", "8443"))
MGMT_TLS_CERT = os.getenv("MGMT_TLS_CERT", "certs/mgmt-web.crt")
MGMT_TLS_KEY = os.getenv("MGMT_TLS_KEY", "certs/mgmt-web.key")
ADMIN_SECRET_TOKEN = os.getenv("ADMIN_SECRET_TOKEN", "")

DOORLOCK_DB_PATH = os.getenv("DOORLOCK_DB_PATH", "door_access.db")

ARGON2_TIME_COST = int(os.getenv("ARGON2_TIME_COST", "3"))
ARGON2_MEMORY_COST = int(os.getenv("ARGON2_MEMORY_COST", "65536"))
ARGON2_PARALLELISM = int(os.getenv("ARGON2_PARALLELISM", "4"))

if not ADMIN_SECRET_TOKEN:
    logging.critical("ADMIN_SECRET_TOKEN not set in .env — refusing to start")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("mgmt-web")

# ---------------------------------------------------------------------------
# Argon2 hasher
# ---------------------------------------------------------------------------
ph = PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST,
    parallelism=ARGON2_PARALLELISM,
    hash_len=32,
    salt_len=16,
)


def hash_pin(pin: str) -> str:
    return ph.hash(pin)


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
@contextmanager
def db_conn(write: bool = False):
    conn = sqlite3.connect(DOORLOCK_DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        if write:
            conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with db_conn(write=True) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                pin_hash TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                revoked_at DATETIME,
                revoked_by TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                username TEXT,
                status TEXT NOT NULL,
                ip_address TEXT,
                reason TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS failed_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                failed_count INTEGER DEFAULT 0,
                lockout_until DATETIME,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(username, ip_address)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target_username TEXT,
                ip_address TEXT,
                details TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_admin_audit_timestamp
            ON admin_audit_logs(timestamp)
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_admin_audit_actor
            ON admin_audit_logs(actor)
            """
        )
        conn.commit()

# ---------------------------------------------------------------------------
# Auth middleware
# ---------------------------------------------------------------------------
def check_admin_auth() -> bool:
    """Constant-time comparison of the Bearer admin token."""
    auth_header = request.headers.get("Authorization", "")
    expected = f"Bearer {ADMIN_SECRET_TOKEN}"
    return hmac.compare_digest(auth_header, expected)


def client_ip() -> str:
    return request.remote_addr or "unknown"


def audit(actor: str, action: str, target_username: str | None, ip: str, details: str = "", conn: sqlite3.Connection | None = None) -> None:
    if conn is not None:
        conn.execute(
            "INSERT INTO admin_audit_logs (actor, action, target_username, ip_address, details) VALUES (?, ?, ?, ?, ?)",
            (actor, action, target_username, ip, details),
        )
    else:
        with db_conn(write=True) as c:
            c.execute(
                "INSERT INTO admin_audit_logs (actor, action, target_username, ip_address, details) VALUES (?, ?, ?, ?, ?)",
                (actor, action, target_username, ip, details),
            )
            c.commit()


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
import re  # noqa: E402

USERNAME_RE = r"^[A-Za-z0-9._-]{3,64}$"


def validate_username(username) -> str | None:
    if not username or not isinstance(username, str):
        return None
    cleaned = username.strip()
    if not cleaned:
        return None
    if not re.match(USERNAME_RE, cleaned):
        return None
    return cleaned


def validate_pin(pin) -> str | None:
    if not pin or not isinstance(pin, str):
        return None
    cleaned = pin.strip()
    if len(cleaned) < 8 or len(cleaned) > 64:
        return None
    return cleaned


# ---------------------------------------------------------------------------
# Quart app
# ---------------------------------------------------------------------------
app = Quart(__name__)


@app.before_serving
async def startup() -> None:
    init_db()


def _require_auth():
    if not check_admin_auth():
        return jsonify({"status": "error", "message": "Unauthorized admin access"}), 401
    return None


@app.post("/api/v1/admin/users")
async def create_user():
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    try:
        data = await request.get_json()
    except Exception:
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400

    if not isinstance(data, dict):
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400

    username = validate_username(data.get("username"))
    pin = validate_pin(data.get("pin"))

    if username is None or pin is None:
        return jsonify({"status": "error", "message": "Invalid username or PIN (min 8 chars)"}), 400

    ip = client_ip()
    actor = ip

    try:
        with db_conn(write=True) as conn:
            # Check existence
            existing = conn.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
            if existing:
                audit(actor, "CREATE_USER_CONFLICT", username, ip, "username already exists")
                return jsonify({"status": "error", "message": "Username already exists"}), 409

            pin_hash = hash_pin(pin)
            conn.execute(
                "INSERT INTO users (username, pin_hash, is_active) VALUES (?, ?, 1)",
                (username, pin_hash),
            )
            audit(actor, "CREATE_USER", username, ip, "user created", conn=conn)
        log.info("User %s created by %s", username, ip)
        return jsonify({"status": "success", "message": f"User {username} registered securely."}), 201
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "Username already exists"}), 409
    except Exception as exc:  # noqa: BLE001
        log.exception("Create user failed: %s", exc)
        return jsonify({"status": "error", "message": "Internal server error"}), 500


@app.get("/api/v1/admin/users")
async def list_users():
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    ip = client_ip()
    actor = ip
    try:
        with db_conn(write=False) as conn:
            rows = conn.execute(
                "SELECT id, username, is_active, created_at, updated_at, revoked_at, revoked_by FROM users ORDER BY username"
            ).fetchall()
            audit(actor, "LIST_USERS", None, ip, f"{len(rows)} users listed")
        users = [
            {
                "id": r["id"],
                "username": r["username"],
                "is_active": bool(r["is_active"]),
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
                "revoked_at": r["revoked_at"],
                "revoked_by": r["revoked_by"],
            }
            for r in rows
        ]
        return jsonify({"status": "success", "users": users}), 200
    except Exception as exc:  # noqa: BLE001
        log.exception("List users failed: %s", exc)
        return jsonify({"status": "error", "message": "Internal server error"}), 500


@app.get("/api/v1/admin/users/<username>")
async def get_user(username: str):
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    ip = client_ip()
    actor = ip
    try:
        with db_conn(write=False) as conn:
            row = conn.execute(
                "SELECT id, username, is_active, created_at, updated_at, revoked_at, revoked_by FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if not row:
                audit(actor, "GET_USER_NOT_FOUND", username, ip, "user not found")
                return jsonify({"status": "error", "message": "User not found"}), 404
            audit(actor, "GET_USER", username, ip, "user retrieved")
        return jsonify({
            "status": "success",
            "user": {
                "id": row["id"],
                "username": row["username"],
                "is_active": bool(row["is_active"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "revoked_at": row["revoked_at"],
                "revoked_by": row["revoked_by"],
            },
        }), 200
    except Exception as exc:  # noqa: BLE001
        log.exception("Get user failed: %s", exc)
        return jsonify({"status": "error", "message": "Internal server error"}), 500


@app.put("/api/v1/admin/users/<username>/pin")
async def update_pin(username: str):
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    try:
        data = await request.get_json()
    except Exception:
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400

    if not isinstance(data, dict):
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400

    pin = validate_pin(data.get("pin"))
    if pin is None:
        return jsonify({"status": "error", "message": "Invalid PIN (min 8 chars)"}), 400

    ip = client_ip()
    actor = ip
    try:
        with db_conn(write=True) as conn:
            row = conn.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
            if not row:
                audit(actor, "UPDATE_PIN_NOT_FOUND", username, ip, "user not found")
                return jsonify({"status": "error", "message": "User not found"}), 404

            pin_hash = hash_pin(pin)
            conn.execute(
                "UPDATE users SET pin_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?",
                (pin_hash, username),
            )
            audit(actor, "UPDATE_PIN", username, ip, "pin changed", conn=conn)
        log.info("PIN updated for user %s by %s", username, ip)
        return jsonify({"status": "success", "message": f"PIN updated for {username}."}), 200
    except Exception as exc:  # noqa: BLE001
        log.exception("Update PIN failed: %s", exc)
        return jsonify({"status": "error", "message": "Internal server error"}), 500


@app.delete("/api/v1/admin/users/<username>")
async def delete_user(username: str):
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    ip = client_ip()
    actor = ip
    try:
        with db_conn(write=True) as conn:
            row = conn.execute(
                "SELECT id, is_active FROM users WHERE username = ?", (username,)
            ).fetchone()
            if not row:
                audit(actor, "DELETE_USER_NOT_FOUND", username, ip, "user not found")
                return jsonify({"status": "error", "message": "User not found"}), 404

            # Soft-delete: set is_active = 0, record revocation
            conn.execute(
                "UPDATE users SET is_active = 0, revoked_at = CURRENT_TIMESTAMP, revoked_by = ? WHERE username = ?",
                (actor, username),
            )
            audit(actor, "SOFT_DELETE_USER", username, ip, "user revoked (soft-delete)", conn=conn)
        log.info("User %s soft-deleted by %s", username, ip)
        return jsonify({"status": "success", "message": f"User {username} has been revoked."}), 200
    except Exception as exc:  # noqa: BLE001
        log.exception("Delete user failed: %s", exc)
        return jsonify({"status": "error", "message": "Internal server error"}), 500


@app.get("/api/v1/admin/access-logs")
async def access_logs():
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    ip = client_ip()
    actor = ip
    try:
        limit = min(int(request.args.get("limit", 50)), 500)
        with db_conn(write=False) as conn:
            rows = conn.execute(
                "SELECT timestamp, username, status, ip_address, reason FROM access_logs ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            audit(actor, "READ_ACCESS_LOGS", None, ip, f"{len(rows)} log entries read")
        logs = [
            {
                "timestamp": r["timestamp"],
                "username": r["username"],
                "status": r["status"],
                "ip_address": r["ip_address"],
                "reason": r["reason"],
            }
            for r in rows
        ]
        return jsonify({"status": "success", "logs": logs}), 200
    except Exception as exc:  # noqa: BLE001
        log.exception("Read access logs failed: %s", exc)
        return jsonify({"status": "error", "message": "Internal server error"}), 500


@app.get("/api/v1/admin/audit-logs")
async def audit_logs():
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    ip = client_ip()
    actor = ip
    try:
        limit = min(int(request.args.get("limit", 50)), 500)
        with db_conn(write=False) as conn:
            rows = conn.execute(
                "SELECT timestamp, actor, action, target_username, ip_address, details FROM admin_audit_logs ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        logs = [
            {
                "timestamp": r["timestamp"],
                "actor": r["actor"],
                "action": r["action"],
                "target_username": r["target_username"],
                "ip_address": r["ip_address"],
                "details": r["details"],
            }
            for r in rows
        ]
        return jsonify({"status": "success", "audit_logs": logs}), 200
    except Exception as exc:  # noqa: BLE001
        log.exception("Read audit logs failed: %s", exc)
        return jsonify({"status": "error", "message": "Internal server error"}), 500


@app.after_request
async def log_response(response):
    log.info(
        "access ip=%s method=%s path=%s status=%d",
        request.remote_addr,
        request.method,
        request.path,
        response.status_code,
    )
    return response


def main() -> None:
    """Entry point for `uv run mgmt-web`."""
    import hypercorn.asyncio
    from hypercorn.config import Config

    config = Config()
    config.bind = [f"{MGMT_HOST}:{MGMT_PORT}"]
    config.certfile = MGMT_TLS_CERT
    config.keyfile = MGMT_TLS_KEY
    config.use_reloader = False

    asyncio.run(hypercorn.asyncio.serve(app, config))


if __name__ == "__main__":
    main()
