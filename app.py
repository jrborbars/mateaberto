"""Doorlock Service — PIN verification and ESP8266 relay command.

Reads user credentials from SQLite but NEVER writes to the `users` table.
All user management is handled exclusively by the Management Web Server.
Relay control is delegated to ESP8266 via HTTP /open command.
"""

import asyncio
import logging
import sqlite3
import sys
import time

from quart import Quart, request, jsonify

import config
from doorlock_common import (
    db_conn,
    hash_pin,
    verify_pin,
    is_legacy_sha256_hash,
    validate_username,
    validate_pin,
    send_esp_open_command,
    get_esp_status,
)

# ---------------------------------------------------------------------------
# Logging (structured, exceptions only in logs — never in responses)
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("doorlock")

# Validate configuration on startup
config_errors = config.validate_config()
if config_errors:
    for err in config_errors:
        log.critical(f"Configuration error: {err}")
    sys.exit(1)



def init_db() -> None:
    """Ensure tables exist and migrate legacy SHA-256 hashes."""

    import hashlib
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
            CREATE INDEX IF NOT EXISTS idx_access_logs_username
            ON access_logs(username)
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_access_logs_timestamp
            ON access_logs(timestamp)
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_failed_attempts_lookup
            ON failed_attempts(username, ip_address)
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_users_active
            ON users(is_active)
            """
        )

        # Pre-populate default test user if table is empty (legacy SHA-256 for v1 compat)
        cur.execute("SELECT COUNT(*) FROM users")
        if cur.fetchone()[0] == 0:
            legacy_hash = hashlib.sha256("87654321".encode()).hexdigest()
            cur.execute(
                "INSERT INTO users (username, pin_hash, is_active) VALUES (?, ?, 1)",
                ("5551234", legacy_hash),
            )
            log.info("Database initialized. Default user: 5551234 (legacy SHA-256, will migrate on first login).")

        conn.commit()

# ---------------------------------------------------------------------------
# Rate limiting (persistent, per username + IP)
# ---------------------------------------------------------------------------
def get_failure_state(conn: sqlite3.Connection, username: str, ip_address: str) -> dict:
    cur = conn.execute(
        "SELECT failed_count, lockout_until FROM failed_attempts WHERE username = ? AND ip_address = ?",
        (username, ip_address),
    )
    row = cur.fetchone()
    if row is None:
        return {"failed_count": 0, "lockout_until": 0.0}
    return {"failed_count": row["failed_count"], "lockout_until": row["lockout_until"] or 0.0}


def record_failure(conn: sqlite3.Connection, username: str, ip_address: str) -> int:
    """Increment failure counter and return new count. Sets lockout if threshold reached."""
    cur = conn.execute(
        "SELECT failed_count FROM failed_attempts WHERE username = ? AND ip_address = ?",
        (username, ip_address),
    )
    row = cur.fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO failed_attempts (username, ip_address, failed_count, updated_at) VALUES (?, ?, 1, CURRENT_TIMESTAMP)",
            (username, ip_address),
        )
        new_count = 1
    else:
        new_count = row["failed_count"] + 1
        conn.execute(
            "UPDATE failed_attempts SET failed_count = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ? AND ip_address = ?",
            (new_count, username, ip_address),
        )

    if new_count >= config.RATE_LIMIT_MAX_FAIL:
        penalty = config.RATE_LIMIT_BASE_PENALTY_S * (new_count - config.RATE_LIMIT_MAX_FAIL + 1)

        lockout_until = time.time() + penalty
        conn.execute(
            "UPDATE failed_attempts SET lockout_until = ? WHERE username = ? AND ip_address = ?",
            (lockout_until, username, ip_address),
        )
        conn.commit()
        return new_count

    conn.commit()
    return new_count


def clear_failures(conn: sqlite3.Connection, username: str, ip_address: str) -> None:
    conn.execute(
        "DELETE FROM failed_attempts WHERE username = ? AND ip_address = ?",
        (username, ip_address),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Access logging
# ---------------------------------------------------------------------------
def log_access(conn: sqlite3.Connection, username: str, status: str, ip_address: str, reason: str = "") -> None:
    conn.execute(
        "INSERT INTO access_logs (username, status, ip_address, reason) VALUES (?, ?, ?, ?)",
        (username, status, ip_address, reason),
    )
    conn.commit()

# ---------------------------------------------------------------------------
# Quart app
# ---------------------------------------------------------------------------
app = Quart(__name__)


@app.before_serving
async def startup() -> None:
    init_db()


@app.post("/api/verify-pin")
async def verify_pin_endpoint():
    client_ip = request.remote_addr or "unknown"
    current_time = time.time()

    # --- Parse and validate input ---
    try:
        data = await request.get_json()
    except Exception:
        log.warning("Invalid JSON payload from %s", client_ip)
        return jsonify({"status": "rejected", "reason": "Invalid payload"}), 400

    if not isinstance(data, dict):
        return jsonify({"status": "rejected", "reason": "Invalid payload"}), 400

    input_user = validate_username(data.get("username"))
    input_pin = validate_pin(data.get("pin"))

    if input_user is None or input_pin is None:
        log.warning("Invalid credentials payload from %s", client_ip)
        return jsonify({"status": "rejected", "reason": "Invalid payload"}), 400

    # --- Rate limiting check ---
    with db_conn(write=True) as conn:
        state = get_failure_state(conn, input_user, client_ip)
        if state["lockout_until"] and current_time < state["lockout_until"]:
            wait_time = int(state["lockout_until"] - current_time)
            log_access(conn, input_user, "DENIED", client_ip, "lockout_active")
            return (
                jsonify({"status": "denied", "reason": f"Locked out. Wait {wait_time}s."}),
                429,
            )

        # --- Look up user (read-only) ---
        cur = conn.execute(
            "SELECT username, pin_hash, is_active FROM users WHERE username = ?",
            (input_user,),
        )
        user_row = cur.fetchone()

    if user_row is None or not user_row["is_active"]:
        # Record failure even for unknown/inactive users (prevents username enumeration via timing)
        with db_conn(write=True) as conn:
            record_failure(conn, input_user, client_ip)
            log_access(conn, input_user, "DENIED", client_ip, "invalid_or_inactive")
        return jsonify({"status": "denied", "reason": "Invalid credentials"}), 401

    stored_hash = user_row["pin_hash"]

    # --- Verify PIN ---
    if verify_pin(stored_hash, input_pin):
        # Successful auth — clear failures, upgrade legacy hash if needed
        with db_conn(write=True) as conn:
            clear_failures(conn, input_user, client_ip)
            # Migrate legacy SHA-256 to argon2 on first successful login
            if is_legacy_sha256_hash(stored_hash):
                new_hash = hash_pin(input_pin)
                conn.execute(
                    "UPDATE users SET pin_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?",
                    (new_hash, input_user),
                )
                conn.commit()
                log.info("User %s migrated from SHA-256 to argon2", input_user)

            log_access(conn, input_user, "GRANTED", client_ip, "")

        log.info("Access GRANTED for user=%s from %s — sending open command to ESP8266", input_user, client_ip)
        send_esp_open_command()

        return jsonify({"status": "granted", "user": input_user}), 200

    # --- Failed auth ---
    with db_conn(write=True) as conn:
        new_count = record_failure(conn, input_user, client_ip)
        log_access(conn, input_user, "DENIED", client_ip, "invalid_credentials")

    log.warning("Access DENIED for user=%s from %s (fail #%d)", input_user, client_ip, new_count)
    return jsonify({"status": "denied", "reason": "Invalid credentials"}), 401


@app.get("/api/health")
async def health():
    """Health check — verifies DB connectivity and ESP8266 status."""
    try:
        with db_conn(write=False) as conn:
            conn.execute("SELECT 1").fetchone()
        esp_status = get_esp_status()
        return jsonify({
            "status": "ok",
            "service": "doorlock",
            "esp_status": esp_status
        }), 200

    except Exception as exc:  # noqa: BLE001
        log.exception("Health check failed: %s", exc)
        return jsonify({"status": "error", "service": "doorlock"}), 503


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
    """Entry point for `uv run doorlock`."""
    import hypercorn.asyncio
    from hypercorn.config import Config

    hypercorn_config = Config()
    hypercorn_config.bind = [f"{config.DOORLOCK_HOST}:{config.DOORLOCK_PORT}"]
    hypercorn_config.use_reloader = False

    asyncio.run(hypercorn.asyncio.serve(app, hypercorn_config))


if __name__ == "__main__":
    main()
