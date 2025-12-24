# Remote Project Manager

Remote Project Manager is a small FastAPI service that manages remote Docker Compose projects over SSH.

## Configuration

Set environment variables for the app configuration.

```bash
export DB_PATH=/data/state.db
export APP_LOG_LEVEL=INFO
export SECRET_SEED="change-me-32-chars-min"
```

Notes:
- The service expects a standard `compose.yaml`, `compose.yml`, `docker-compose.yml`, or `docker-compose.yaml` in each project folder.
- `APP_LOG_LEVEL` (optional) controls logging verbosity (e.g. `DEBUG`, `INFO`, `WARNING`).
- Hosts and backup configuration live in the SQLite DB (see below).
- To enable HTTPS, set `SSL_CERTFILE` and `SSL_KEYFILE` (see HTTPS section).


## Run locally

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
DB_PATH=./state.db APP_LOG_LEVEL=INFO uvicorn app.main:app --reload
```

## Run in Docker

```bash
docker build -t ssh-compose-manager .

docker run --rm -p 8000:8000 \
  -e DB_PATH=/data/state.db \
  -e APP_LOG_LEVEL=INFO \
  -v $(pwd)/state.db:/data/state.db \
  ssh-compose-manager
```

## HTTPS

To serve the UI/API over HTTPS, provide a certificate and key to uvicorn. The Docker entrypoint will enable TLS when both environment variables are set.

Local example:

```bash
DB_PATH=./state.db APP_LOG_LEVEL=INFO \
SSL_CERTFILE=./certs/server.crt SSL_KEYFILE=./certs/server.key \
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Docker example:

```bash
docker run --rm -p 8000:8000 \
  -e DB_PATH=/data/state.db \
  -e APP_LOG_LEVEL=INFO \
  -e SSL_CERTFILE=/certs/server.crt \
  -e SSL_KEYFILE=/certs/server.key \
  -v $(pwd)/state.db:/data/state.db \
  -v $(pwd)/certs:/certs:ro \
  ssh-compose-manager
```

## State refresh

The service refreshes project status and update availability on separate timers. Configure the status interval with `STATE_REFRESH_SECONDS` (default: 300) and the update interval with `UPDATE_REFRESH_SECONDS` (default: 720). Update checks are rate-limited to five registry manifest requests per hour. Set either to `0` to disable the periodic refresh and rely on manual host refresh endpoints. Intervals persist to the SQLite DB at `DB_PATH` when configured; ensure the directory exists and is writable.

## Authentication

The API requires a bearer token for all non-static endpoints. Tokens are created via `POST /auth/token` and must be supplied in the `Authorization: Bearer <token>` header. The web UI handles this automatically and stores the token in a cookie.

Defaults stored in the `settings` table on first DB initialization:
- `token_expiry`: 300 seconds.
- Default user: `admin` / `changemenow` (password stored as HMAC-SHA-512 with `secret_seed`).

Token creation flow:
1. Client sends `{ "username": "<user>", "password": "<password>" }` to `/auth/token`.
2. Server hashes the password with `SECRET_SEED`, validates it, inserts a token row, and returns a base64-encoded JSON payload: `{ "username", "id", "expiration" }`.

Token validation on requests:
- Bearer token is base64-decoded to JSON.
- `username` must exist in `users`.
- `expiration` must be in the future.
- `id`/`expiration` must match a row in `tokens`.

## Scheduled backups

Scheduled backups run on the cron-like schedule defined via the Backup schedule modal or the `/backup/schedule` API (UTC). Scheduled backups require `DB_PATH` to persist settings and a row in the `backups` table. Use the Schedule for dropdown in the modal to set per-project overrides (or call `PUT /hosts/{host_id}/projects/{project}/backup/settings` with `cron_override`).

## API endpoints

- `GET /hosts`
- `GET /hosts/{host_id}/projects`
- `GET /hosts/{host_id}/projects/{project}/status`
- `GET /hosts/{host_id}/projects/{project}/logs?tail=200`
- `GET /hosts/{host_id}/projects/{project}/logs/stream`
- `GET /hosts/{host_id}/projects/{project}/compose`
- `POST /hosts/{host_id}/projects/{project}/compose/validate`
- `PUT /hosts/{host_id}/projects/{project}/compose`
- `POST /hosts/{host_id}/projects/{project}/start`
- `POST /hosts/{host_id}/projects/{project}/stop`
- `POST /hosts/{host_id}/projects/{project}/restart`
- `POST /hosts/{host_id}/projects/{project}/backup`
- `GET /hosts/{host_id}/projects/{project}/backup/stream`
- `POST /hosts/{host_id}/projects/{project}/backup/stop`
- `GET /hosts/{host_id}/projects/{project}/backup/settings`
- `PUT /hosts/{host_id}/projects/{project}/backup/settings`
- `POST /hosts/{host_id}/projects/{project}/services/{service}/start`
- `GET /hosts/{host_id}/projects/{project}/services/{service}/actions/{action}/stream`
- `POST /hosts/{host_id}/projects/{project}/services/{service}/actions/{action}/stop`
- `POST /hosts/{host_id}/projects/{project}/services/{service}/stop`
- `POST /hosts/{host_id}/projects/{project}/services/{service}/restart`
- `GET /hosts/{host_id}/projects/{project}/updates`
- `POST /hosts/{host_id}/projects/{project}/update`
- `GET /state`
- `GET /hosts/{host_id}/state`
- `GET /state/interval`
- `GET /backup/schedule`
- `PUT /state/interval`
- `GET /update/interval`
- `PUT /update/interval`
- `PUT /backup/schedule`
- `POST /hosts/{host_id}/state/refresh`
- `POST /hosts/{host_id}/projects/{project}/state/refresh`

Response notes:
- `/hosts/{host_id}/projects` returns `projects` (names) and `project_paths` (name to full path).

## OpenAPI docs

OpenAPI documentation is available at:
- `GET /docs` (Swagger UI)
- `GET /openapi.json` (OpenAPI JSON)
- `GET /redoc` (ReDoc UI)

Use the Authorize button in the Swagger UI to provide the bearer token from `/auth/token`.

## Web UI

Open `http://localhost:8000/` to access the management dashboard. Use the Configuration button to manage hosts, backups, and refresh intervals. The Compose button lets you view or edit the project compose file. The Backup schedule button opens the scheduling modal.

## Backups

Configure the `backups` table to enable project backups via rsync, triggered from the managed host to the backup server. This requires `rsync` installed on each managed host. For `protocol=ssh`, `sshpass` and SSH access from the host to the backup server are required. For `protocol=rsync`, the backup server must expose an rsync daemon (port 873), and `base_path` should point to the rsync module and subpath.

Backup path examples (for project `myapp`):
- `protocol=ssh` with `base_path=/Servers` writes to `/Servers/myapp` on the backup server.
- `protocol=rsync` with `base_path=Backups/Servers` writes to `rsync://backup-host/Backups/Servers/myapp`.
