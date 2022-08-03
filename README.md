# Door Access Control System v2.0


Door access control running on a Rockchip RK322x TV box. An ESP8266 numeric keypad
sends a user ID + PIN to a local Python API; on success a physical relay unlocks the door.

**Architecture (v2.0):**
- **Doorlock Service** (`app.py`, port 8000 HTTP) — verifies PINs from the ESP8266 and triggers the relay. Read-only on the `users` table.
- **Management Web Server** (`mgmt_web.py`, port 8443 TLS) — the **only** service allowed to modify users/PINs. Runs on localhost, protected by self-signed TLS + Bearer token.
- **ESP8266 Firmware** (`esp8266.cpp`) — keypad + relay, non-blocking, WiFi auto-reconnect.

---

## Quick Start

### 1. Install Python dependencies (UV)

```bash
# Install UV (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Sync project dependencies
uv sync
```

### 2. Configure environment

Copy `.env` and adjust values:

```bash
cp .env .env.local   # or edit .env directly
```

**Critical:** Generate a strong admin token and set it in `.env`:

```bash
openssl rand -base64 32
```

Then set `ADMIN_SECRET_TOKEN=<that-value>` in `.env`.

Also set `DOORLOCK_DB_PATH` to your SQLite file location.

### 3. Generate TLS certificate (for management server)

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/mgmt-web.key -out certs/mgmt-web.crt \
  -days 365 -nodes -subj "/CN=localhost/O=DoorLock/C=BR"
chmod 600 certs/mgmt-web.key certs/mgmt-web.crt
```

### 4. Run the services

**Option A — Direct (for testing):**

```bash
# Terminal 1: Doorlock Service
uv run doorlock

# Terminal 2: Management Web Server
uv run mgmt-web
```

**Option B — systemd (production):**

```bash
sudo cp doorlock.service mgmt-web.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now doorlock.service
sudo systemctl enable --now mgmt-web.service
```

---

## API Reference

### Doorlock Service — `http://<host>:8000`

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/verify-pin` | None | Verify username+PIN from ESP8266 |
| `GET`  | `/api/health` | None | Health check |

**Example — verify PIN:**

```bash
curl -X POST http://192.168.22.13:8000/api/verify-pin \
  -H "Content-Type: application/json" \
  -d '{"username": "5551234", "pin": "87654321"}'
```

Responses:
- `200` — `{ "status": "granted", "user": "5551234" }` → relay triggers
- `401` — `{ "status": "denied", "reason": "Invalid credentials" }`
- `429` — `{ "status": "denied", "reason": "Locked out. Wait 30s." }`
- `400` — `{ "status": "rejected", "reason": "Invalid payload" }`

### Management Web Server — `https://127.0.0.1:8443`

All endpoints require `Authorization: Bearer <ADMIN_SECRET_TOKEN>` over TLS.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/admin/users` | Create user (`{username, pin}`) |
| `GET`  | `/api/v1/admin/users` | List all users |
| `GET`  | `/api/v1/admin/users/<username>` | Get user details |
| `PUT`  | `/api/v1/admin/users/<username>/pin` | Change PIN |
| `DELETE` | `/api/v1/admin/users/<username>` | Soft-revoke user |
| `GET`  | `/api/v1/admin/access-logs` | Read access logs |
| `GET`  | `/api/v1/admin/audit-logs` | Read admin audit logs |

**Example — create a user:**

```bash
curl -k https://127.0.0.1:8443/api/v1/admin/users \
  -H "Authorization: Bearer <ADMIN_SECRET_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"username": "9998888", "pin": "11223344"}'
```

(`-k` is needed because the certificate is self-signed.)

---

## ESP8266 Firmware

Flash `esp8266.cpp` to your ESP8266. Before compiling, set these in the sketch or via
`-D` compiler flags:

- `WIFI_SSID` — your WiFi SSID
- `WIFI_PASSWORD` — your WiFi password
- `API_URL` — full URL to the doorlock service, e.g. `http://192.168.22.13:8000/api/verify-pin`

The keypad flow:
1. Enter user ID → press `*`
2. Enter PIN (≥8 digits) → press `#`
3. On success, relay activates for 3 seconds

---

## Security Checklist

- [ ] `ADMIN_SECRET_TOKEN` is a strong random value (≥32 chars), set in `.env`
- [ ] `.env` has permissions `0600` and is **never committed** to version control
- [ ] Management Web Server binds to `127.0.0.1:8443` only (not exposed to LAN/WAN)
- [ ] Self-signed TLS certificate is in place for the management server
- [ ] Default PIN (`87654321`) changed on first use
- [ ] `door_access.db` file permissions are `0600`
- [ ] PINs are hashed with argon2 (legacy SHA-256 hashes migrate on first login)
- [ ] Rate limiting is persistent per username + IP (survives restarts)

---

## Project Structure

```
/mnt/remote/
├── app.py                  # Doorlock Service (port 8000 HTTP)
├── mgmt_web.py             # Management Web Server (port 8443 TLS)
├── esp8266.cpp             # ESP8266 keypad firmware
├── door_access.db          # SQLite database
├── .env                    # Secrets & configuration (NOT in git)
├── .gitignore              # Git ignore rules
├── pyproject.toml          # UV project definition + dependencies
├── doorlock.service        # systemd unit for Doorlock Service
├── mgmt-web.service        # systemd unit for Management Web Server
├── certs/                  # Self-signed TLS certificates
├── PRD.md                  # Product Requirements Document (v2.0)
├── README.md               # This file
└── history.md              # Unrelated CPU benchmarking notes (archived)
```

---

## Notes

- `history.md` contains unrelated CPU benchmarking conversations from the project's exploration phase. It is **not** part of the door access control system and is preserved here for reference only.
- All communication between the Management Web Server and admin clients uses TLS. The Doorlock Service ↔ ESP8266 path remains local HTTP on the LAN.
- **Only the Management Web Server may modify the `users` table.** The Doorlock Service reads credentials but never writes them. No other client — even from the same network — can modify doorlock state.


## last iteration

The implementation is complete. Here is a summary of everything that was done:

---

## Summary — Door Access Control System v2.0

### What was built

A complete door access control system with **strict separation between door control and user management**, running on a Rockchip RK322x TV box, using **UV + `pyproject.toml`** for Python dependency management.

### Files created/modified

| File | Purpose |
|------|---------|
| `pyproject.toml` | UV project definition with pinned dependencies (quart, hypercorn, argon2-cffi, python-dotenv) |
| `uv.lock` | Deterministic lock file generated by UV |
| `.env` | Secrets and configuration (`0600` permissions, in `.gitignore`) |
| `app.py` | **Doorlock Service** — PIN verification + relay trigger (port 8000 HTTP, read-only on `users`) |
| `mgmt_web.py` | **Management Web Server** — sole writer to `users` table (port 8443 TLS, localhost only) |
| `esp8266.cpp` | ESP8266 firmware — non-blocking relay, WiFi reconnect, ArduinoJSON |
| `doorlock.service` | systemd unit for Doorlock Service |
| `mgmt-web.service` | systemd unit for Management Web Server |
| `certs/mgmt-web.crt` + `certs/mgmt-web.key` | Self-signed TLS certificate |
| `README.md` | Updated with placeholders, setup, security checklist |
| `PRD.md` | Complete Product Requirements Document (sections 1-10) |
| `.gitignore` | Excludes `.env`, `door_access.db`, `.venv`, `certs/` |

### Key security improvements implemented

1. **Argon2 PIN hashing** (`argon2-cffi`) with per-user salt — replaces unsalted SHA-256
2. **Legacy SHA-256 migration** — hashes transparently upgraded to argon2 on first successful login
3. **Environment-based secrets** — `ADMIN_SECRET_TOKEN` from `.env`, never hardcoded
4. **Constant-time comparison** — `hmac.compare_digest` for admin token
5. **Persistent rate limiting** — per `username + IP` in SQLite, survives restarts
6. **Self-signed TLS** — management server on `127.0.0.1:8443` only
7. **Soft-delete users** — `is_active = 0` with `revoked_at`/`revoked_by` audit trail
8. **Generic error messages** — exceptions logged server-side only
9. **Input validation** — username charset/length, PIN length (8-64 chars)
10. **SQLite hardening** — WAL mode, `busy_timeout=30000`, `foreign_keys=ON`

### Architecture: detached Management Web Server

- **Doorlock Service** (`app.py`): reads `users`, writes `access_logs`/`failed_attempts`. **Never writes to `users`.**
- **Management Web Server** (`mgmt_web.py`): sole entity authorized to `INSERT/UPDATE/DELETE` on `users`. No other client — even from the same network — can modify doorlock state.
- Door unlock flow remains local: ESP8266 → Doorlock Service → relay.

### Verified integration tests

All tests passed:
- ✅ Health check returns `{"status":"ok"}`
- ✅ Correct PIN → `{"status":"granted"}`
- ✅ Wrong PIN → `{"status":"denied"}`
- ✅ 4th failure → `429 Locked out. Wait 29s.`
- ✅ Mgmt server creates user → doorlock verifies it
- ✅ Mgmt server updates PIN → doorlock accepts new PIN, rejects old
- ✅ Mgmt server soft-deletes user → doorlock denies access
- ✅ Mgmt server without Bearer token → 401
- ✅ Argon2 migration confirmed (legacy SHA-256 → argon2 on first login)

### Next steps for deployment

1. Generate a strong `ADMIN_SECRET_TOKEN`: `openssl rand -base64 32`
2. Set it in `.env` (replace `CHANGE_ME_GENERATE_A_STRONG_RANDOM_TOKEN`)
3. Adjust `DOORLOCK_DB_PATH` if needed
4. Install systemd units: `sudo cp doorlock.service mgmt-web.service /etc/systemd/system/`
5. Enable services: `sudo systemctl enable --now doorlock.service mgmt-web.service`
6. Flash `esp8266.cpp` to ESP8266 with correct `WIFI_SSID`, `WIFI_PASSWORD`, `API_URL`
