# Remote Project Manager

Remote Project Manager (RPM) is a FastAPI service that manages Docker Compose projects over SSH, with a web UI for hosts, backups, schedules, and user management.

## Configuration

Set environment variables before starting the service.

```bash
export DB_PATH=/data/state.db
export SECRET_SEED="change-me-32-chars-min"
export APP_LOG_LEVEL=INFO
```

Optional settings:
- `STATE_REFRESH_SECONDS` (default: `300`) controls project status refresh cadence.
- `UPDATE_REFRESH_SECONDS` (default: `720`) controls update status refresh cadence.
- `UPDATE_CHECKS_ENABLED` (default: `true`) enables or disables registry update checks.
- `SSL_CERTFILE` and `SSL_KEYFILE` enable HTTPS (see HTTPS section).

Notes:
- `DB_PATH` must point to a writable file; the database is created if missing.
- The service expects a `compose.yaml`, `compose.yml`, `docker-compose.yml`, or `docker-compose.yaml` in each project folder.
- Hosts, backups, schedules, and users are managed in the UI and stored in SQLite.

## Run locally

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
DB_PATH=./state.db SECRET_SEED="change-me-32-chars-min" APP_LOG_LEVEL=INFO uvicorn app.main:app --reload
```

## Run in Docker

```bash
docker build -t remote-project-manager .

docker run --rm -p 8000:8000 \
  -e DB_PATH=/data/state.db \
  -e SECRET_SEED="change-me-32-chars-min" \
  -e APP_LOG_LEVEL=INFO \
  -v $(pwd)/state.db:/data/state.db \
  remote-project-manager
```

## HTTPS

To serve the UI/API over HTTPS, provide a certificate and key to uvicorn. The Docker entrypoint will enable TLS when both environment variables are set.

Local example:

```bash
DB_PATH=./state.db SECRET_SEED="change-me-32-chars-min" APP_LOG_LEVEL=INFO \
  SSL_CERTFILE=./certs/server.crt SSL_KEYFILE=./certs/server.key \
  uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Docker example:

```bash
docker run --rm -p 8000:8000 \
  -e DB_PATH=/data/state.db \
  -e SECRET_SEED="change-me-32-chars-min" \
  -e APP_LOG_LEVEL=INFO \
  -e SSL_CERTFILE=/certs/server.crt \
  -e SSL_KEYFILE=/certs/server.key \
  -v $(pwd)/state.db:/data/state.db \
  -v $(pwd)/certs:/certs:ro \
  remote-project-manager
```

## Authentication

The API requires a bearer token for all non-static endpoints. Tokens are created via `POST /auth/token` and must be supplied in the `Authorization: Bearer <token>` header. The web UI handles this automatically and stores the token in a cookie.

Defaults stored in the database on first initialization:
- `token_expiry`: `300` seconds.
- Default user: `admin` / `changemenow`.

Token creation flow:
1. Client sends `{ "username": "<user>", "password": "<password>" }` to `/auth/token`.
2. Server hashes the password with `SECRET_SEED`, validates it, inserts a token row, and returns a base64-encoded JSON payload: `{ "username", "id", "expiration", "role" }`.

Token validation:
- Bearer token is base64-decoded to JSON.
- `username` must exist in `users`.
- `expiration` must be in the future.
- `id`/`expiration` must match a row in `tokens`.


User roles:
- **admin**: full access to all configuration, backup/restore, and project actions.
- **power**: can run project/service actions (start/stop/restart/update/refresh) but cannot delete projects, edit compose files, or run backups/restore.
- **normal**: read-only access to status, stats, and logs.

## State refresh & updates

The service refreshes project status and update availability on separate timers. Set `STATE_REFRESH_SECONDS` and `UPDATE_REFRESH_SECONDS` to control cadence (set either to `0` to disable periodic refresh). Update checks are rate-limited to five registry manifest requests per hour and can be toggled with `UPDATE_CHECKS_ENABLED`.

## Web UI

Open `http://localhost:8000/` to access the management dashboard. The UI provides:
- Host and project management (scan, start/stop/restart, compose editor, logs).
- Compose editor with syntax highlighting and a review/save diff workflow.
- Backup configuration, scheduling, restore workflows, and background events.
- Configuration tabs for hosts, backups, users, and misc intervals.
- Status, update, and project details visibility.
- UI actions are enabled/disabled based on the signed-in user role.

### UI overview

The UI is split into three primary areas:
- **Hosts**: manage connections, scan for projects, and trigger host-level actions.
- **Projects**: table view of project status, updates, actions, details, and compose editing.
- **Details & Modals**: compose editor, logs, backup schedule, restore, commands, and background events.

## Backups & restore

Backups are performed from each managed host to the configured backup target using `rsync`.

Requirements:
- `rsync` installed on each managed host.
- For `protocol=ssh`, the host must reach the backup server over SSH (and `sshpass` if using password auth).
- For `protocol=rsync`, the backup server must run an rsync daemon (port 873).

Backup path examples (for project `myapp`):
- `protocol=ssh` with `base_path=/Servers` writes to `/Servers/myapp` on the backup server.
- `protocol=rsync` with `base_path=Backups/Servers` writes to `rsync://backup-host/Backups/Servers/myapp`.

## Scheduled backups

Scheduled backups use cron-like expressions configured via the Backup schedule modal or `PUT /backup/schedule`. Per-project overrides are available in the schedule modal or via `PUT /hosts/{host_id}/projects/{project}/backup/settings`.

## OpenAPI docs

OpenAPI documentation is available at:
- `GET /docs` (Swagger UI)
- `GET /openapi.json` (OpenAPI JSON)
- `GET /redoc` (ReDoc UI)

Use the Authorize button in Swagger UI to provide the bearer token from `/auth/token`.
