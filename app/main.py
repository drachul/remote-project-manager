import asyncio
import base64
import contextlib
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import string
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

from croniter import croniter, CroniterBadCronError, CroniterBadDateError

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import compose
from .config import (
    AppConfig,
    BackupConfig,
    ConfigError,
    HostConfig,
    get_host_config,
    load_config,
)
from .models import (
    StateRefreshResponse,
    StateResponse,
    IntervalRequest,
    IntervalResponse,
    BackupScheduleRequest,
    BackupScheduleResponse,
    BackupSettingsRequest,
    BackupSettingsResponse,
    HostConfigEntry,
    BackupConfigEntry,
    SimpleStatusResponse,
    ComposeFileResponse,
    ComposeFileUpdateRequest,
    ProjectCreateRequest,
    ProjectCreateResponse,
    ComposeValidateRequest,
    ComposeValidateResponse,
    ContainerStatus,
    HostInfo,
    HostStateResponse,
    LogsResponse,
    OperationResponse,
    ProjectListResponse,
    ProjectStatusResponse,
    UpdateApplyResponse,
    UpdateCheckResponse,
    AuthTokenRequest,
    UserConfigEntry,
    UserCreateRequest,
    UserUpdateRequest,
    RunToComposeRequest,
    RunToComposeResponse,
)
from .ssh import SSHError, stream_ssh_command

app = FastAPI(title="Remote Project Manager", version="0.1.0")


def _custom_openapi_schema() -> dict:
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        routes=app.routes,
    )
    schema.setdefault("components", {}).setdefault("securitySchemes", {})[
        "bearerAuth"
    ] = {
        "type": "http",
        "scheme": "bearer",
    }
    schema["security"] = [{"bearerAuth": []}]
    app.openapi_schema = schema
    return app.openapi_schema


app.openapi = _custom_openapi_schema
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
logger = logging.getLogger("rpm")
TOKEN_CLEANUP_INTERVAL_SECONDS = 60


@app.get("/")
def ui_index() -> HTMLResponse:
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(html)


@app.on_event("startup")
async def load_settings() -> None:
    app.state.loop = asyncio.get_running_loop()
    app.state.config = load_config()
    app.state.config = _load_config_from_db(app.state.config)
    _configure_logging(app.state.config.log_level)
    logger.info("Starting Remote Project Manager")
    app.state.state_lock = asyncio.Lock()
    app.state.backup_lock = asyncio.Lock()
    app.state.backup_controls = {}
    app.state.action_lock = asyncio.Lock()
    app.state.action_controls = {}
    app.state.backup_schedule_map = {}
    app.state.backup_schedule_event = asyncio.Event()
    app.state.db_path = _db_path()
    if app.state.db_path:
        _ensure_db(app.state.db_path)
        app.state.secret_seed = _load_secret_seed()
        app.state.token_expiry_seconds = _load_token_expiry()
    app.state.state_interval_seconds = _load_interval_setting(
        "state_interval_seconds", _state_interval_seconds()
    )
    app.state.update_interval_seconds = _load_interval_setting(
        "update_interval_seconds", _update_interval_seconds()
    )
    app.state.state_task = _start_state_task()
    app.state.update_task = _start_update_task()
    app.state.backup_task = _start_backup_task()
    app.state.token_cleanup_task = _start_token_cleanup_task()
    logger.info("Startup complete")


@app.on_event("shutdown")
async def shutdown_tasks() -> None:
    logger.info("Shutting down")
    for task_name in ("state_task", "update_task", "backup_task", "token_cleanup_task"):
        task = getattr(app.state, task_name, None)
        if not task:
            continue
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if _skip_auth(path, request.method):
        return await call_next(request)
    try:
        _verify_request_token(request)
    except HTTPException as exc:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    return await call_next(request)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _configure_logging(level_name: Optional[str]) -> None:
    level_name = (level_name or "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False


def _skip_auth(path: str, method: str) -> bool:
    if method.upper() == "OPTIONS":
        return True
    if path == "/":
        return True
    if path.startswith("/static/"):
        return True
    if path in ("/docs", "/openapi.json", "/redoc", "/docs/oauth2-redirect"):
        return True
    if path == "/auth/token":
        return True
    return False


def _parse_token_payload(token: str) -> dict:
    padded = token + "=" * (-len(token) % 4)
    try:
        raw = base64.b64decode(padded)
        payload = json.loads(raw.decode())
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Token decode failed.") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=401, detail="Token payload invalid.")
    return payload


def _parse_token_expiration(value: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Token expiration invalid.") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _parse_db_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _verify_request_token(request: Request) -> None:
    header = request.headers.get("authorization")
    if not header:
        raise HTTPException(status_code=401, detail="Authorization header missing.")
    if not header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Authorization must be Bearer token.")
    token = header.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Authorization token missing.")
    payload = _parse_token_payload(token)
    username = payload.get("username")
    token_id = payload.get("id")
    expiration_value = payload.get("expiration")
    if not username or not token_id or not expiration_value:
        raise HTTPException(status_code=401, detail="Token payload incomplete.")
    expiration = _parse_token_expiration(str(expiration_value))
    if expiration < _now():
        raise HTTPException(status_code=401, detail="Token expired.")
    path = _require_db_path()
    with _open_db(path) as conn:
        user_row = conn.execute(
            "SELECT password FROM users WHERE username = ?", (username,)
        ).fetchone()
        if not user_row:
            raise HTTPException(status_code=401, detail="User not found.")
        token_row = conn.execute(
            "SELECT 1 FROM tokens WHERE id = ? AND expiration = ?",
            (token_id, expiration_value),
        ).fetchone()
        if not token_row:
            raise HTTPException(status_code=401, detail="Token not recognized.")
    request.state.username = username


def _state_interval_seconds() -> int:
    raw = os.environ.get("STATE_REFRESH_SECONDS", "300")
    try:
        value = int(raw)
    except ValueError:
        return 300
    return max(0, value)


def _update_interval_seconds() -> int:
    raw = os.environ.get("UPDATE_REFRESH_SECONDS", "720")
    try:
        value = int(raw)
    except ValueError:
        return 720
    return max(0, value)


def _next_cron_run(cron_expr: str, base_time: datetime) -> Optional[datetime]:
    try:
        iterator = croniter(cron_expr, base_time)
        return iterator.get_next(datetime)
    except (CroniterBadCronError, CroniterBadDateError, ValueError):
        return None


def _normalize_db_path(path: str) -> str:
    expanded = os.path.expandvars(os.path.expanduser(path))
    normalized = os.path.abspath(expanded)
    if expanded.endswith(os.sep) or (os.altsep and expanded.endswith(os.altsep)):
        return os.path.join(normalized, "state.db")
    if os.path.isdir(normalized):
        return os.path.join(normalized, "state.db")
    return normalized


def _db_path() -> Optional[str]:
    raw = _config().db_path
    if not raw:
        return None
    return _normalize_db_path(raw)


def _require_db_path() -> str:
    path = app.state.db_path
    if not path:
        raise HTTPException(status_code=400, detail="DB_PATH is not configured.")
    _ensure_db(path)
    return path


def _generate_secret_seed() -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(32))


def _hmac_base64(key: str, message: str) -> str:
    digest = hmac.new(key.encode(), message.encode(), hashlib.sha512).digest()
    return base64.b64encode(digest).decode()


def _hash_password(secret_seed: str, password: str) -> str:
    return _hmac_base64(secret_seed, password)


def _read_setting_value(conn: sqlite3.Connection, key: str) -> Optional[str]:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def _ensure_setting_value(conn: sqlite3.Connection, key: str, value: str) -> str:
    current = _read_setting_value(conn, key)
    if current is not None:
        return current
    conn.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (key, value))
    return value


def _ensure_db(path: str) -> None:
    if os.path.isdir(path):
        raise ConfigError(f"db_path points to a directory: {path}")
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    try:
        with sqlite3.connect(path) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            _ensure_setting_value(conn, "token_expiry", "300")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS hosts ("
                "id TEXT PRIMARY KEY NOT NULL, "
                "project_root TEXT, "
                "ssh_address TEXT, "
                "ssh_username TEXT, "
                "ssh_key TEXT, "
                "ssh_port INTEGER"
                ")"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS project_state ("
                "host_id TEXT NOT NULL, "
                "id TEXT NOT NULL, "
                "path TEXT NOT NULL, "
                "overall_status TEXT, "
                "updates_available BOOLEAN DEFAULT 0, "
                "sleeping BOOLEAN DEFAULT 0, "
                "refreshed_at DATETIME, "
                "PRIMARY KEY (host_id, id), "
                "FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE"
                ")"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS backups ("
                "id TEXT PRIMARY KEY NOT NULL, "
                "address TEXT, "
                "username TEXT, "
                "password TEXT, "
                "base_path TEXT, "
                "protocol TEXT, "
                "port INTEGER, "
                "enabled BOOLEAN DEFAULT 1"
                ")"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS service_state ("
                "host_id TEXT NOT NULL, "
                "project_id TEXT NOT NULL, "
                "id TEXT NOT NULL, "
                "status TEXT, "
                "update_available BOOLEAN DEFAULT 0, "
                "update_checked_at DATETIME, "
                "refreshed_at DATETIME, "
                "PRIMARY KEY (host_id, project_id, id), "
                "FOREIGN KEY (host_id, project_id) REFERENCES project_state(host_id, id) "
                "ON DELETE CASCADE"
                ")"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS users ("
                "username TEXT PRIMARY KEY, "
                "password TEXT NOT NULL, "
                "last_login DATETIME"
                ")"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS tokens ("
                "id TEXT NOT NULL, "
                "expiration DATETIME"
                ")"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS backup_state ("
                "host_id TEXT NOT NULL, "
                "project TEXT NOT NULL, "
                "enabled BOOLEAN DEFAULT 0, "
                "cron_override TEXT, "
                "last_backup_at DATETIME, "
                "last_backup_success BOOLEAN, "
                "last_backup_message TEXT, "
                "PRIMARY KEY (host_id, project), "
                "FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE"
                ")"
            )
            _ensure_column(conn, "service_state", "update_checked_at", "DATETIME")
            _ensure_column(conn, "backup_state", "last_backup_message", "TEXT")
            _ensure_column(conn, "backup_state", "cron_override", "TEXT")
            _ensure_column(conn, "project_state", "sleeping", "BOOLEAN DEFAULT 0")
            _ensure_column(conn, "backups", "enabled", "BOOLEAN DEFAULT 1")
            admin_exists = conn.execute(
                "SELECT 1 FROM users WHERE username = ?", ("admin",)
            ).fetchone()
            if not admin_exists:
                admin_hash = _hash_password(_secret_seed(), "changemenow")
                conn.execute(
                    "INSERT INTO users (username, password, last_login) VALUES (?, ?, ?)",
                    ("admin", admin_hash, None),
                )
    except sqlite3.OperationalError as exc:
        logger.exception("DB init failed for path=%s", path)
        raise ConfigError(f"Unable to open db_path {path}: {exc}") from exc


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    existing = {row[1] for row in rows}
    if column in existing:
        return
    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _read_interval_setting(path: str, key: str) -> Optional[int]:
    with sqlite3.connect(path) as conn:
        row = conn.execute(
            "SELECT value FROM settings WHERE key = ?", (key,)
        ).fetchone()
    if not row:
        return None
    try:
        return max(0, int(row[0]))
    except ValueError:
        return None


def _write_interval_setting(path: str, key: str, value: int) -> None:
    with sqlite3.connect(path) as conn:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, str(value)),
        )


def _read_setting(path: str, key: str) -> Optional[str]:
    with sqlite3.connect(path) as conn:
        row = conn.execute(
            "SELECT value FROM settings WHERE key = ?", (key,)
        ).fetchone()
    if not row:
        return None
    return row[0]


def _write_setting(path: str, key: str, value: Optional[str]) -> None:
    with sqlite3.connect(path) as conn:
        if value is None:
            conn.execute("DELETE FROM settings WHERE key = ?", (key,))
            return
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


def _load_interval_setting(key: str, default_value: int) -> int:
    path = app.state.db_path
    if not path:
        return default_value
    _ensure_db(path)
    value = _read_interval_setting(path, key)
    if value is None:
        _write_interval_setting(path, key, default_value)
        return default_value
    return value


def _persist_interval_setting(key: str, value: int) -> None:
    path = app.state.db_path
    if not path:
        return
    _ensure_db(path)
    _write_interval_setting(path, key, value)


def _load_backup_cron() -> Optional[str]:
    cron, enabled = _load_backup_cron_state()
    if not enabled:
        return None
    return cron


def _load_backup_cron_state() -> tuple[Optional[str], bool]:
    path = app.state.db_path
    if not path:
        return None, False
    _ensure_db(path)
    cron = _read_setting(path, "backup_cron")
    enabled_value = _read_setting(path, "backup_cron_enabled")
    if enabled_value is None:
        return cron, bool(cron)
    return cron, enabled_value.strip().lower() in ("1", "true", "yes", "on")


def _persist_backup_cron(cron_expr: Optional[str], enabled: Optional[bool] = None) -> None:
    path = app.state.db_path
    if not path:
        return
    _ensure_db(path)
    _write_setting(path, "backup_cron", cron_expr)
    if enabled is not None:
        _write_setting(path, "backup_cron_enabled", "1" if enabled else "0")


def _ensure_backup_entries(host_id: str, projects: List[str]) -> None:
    path = app.state.db_path
    if not path or not projects:
        return
    _ensure_db(path)
    with _open_db(path) as conn:
        for project in projects:
            conn.execute(
                "INSERT INTO backup_state (host_id, project, enabled) VALUES (?, ?, 0) "
                "ON CONFLICT(host_id, project) DO NOTHING",
                (host_id, project),
            )


def _load_backup_settings(
    host_id: Optional[str] = None,
) -> Dict[tuple[str, str], dict]:
    path = app.state.db_path
    if not path:
        return {}
    _ensure_db(path)
    with _open_db(path) as conn:
        conn.row_factory = sqlite3.Row
        if host_id:
            rows = conn.execute(
                "SELECT host_id, project, enabled, cron_override, last_backup_at, "
                "last_backup_success, last_backup_message "
                "FROM backup_state WHERE host_id = ?",
                (host_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT host_id, project, enabled, cron_override, last_backup_at, "
                "last_backup_success, last_backup_message "
                "FROM backup_state"
            ).fetchall()
    settings = {}
    for row in rows:
        settings[(row["host_id"], row["project"])] = {
            "enabled": bool(row["enabled"]),
            "cron_override": row["cron_override"],
            "last_backup_at": _parse_timestamp(row["last_backup_at"]),
            "last_backup_success": (
                None
                if row["last_backup_success"] is None
                else bool(row["last_backup_success"])
            ),
            "last_backup_message": row["last_backup_message"],
        }
    return settings


def _set_backup_enabled(host_id: str, project: str, enabled: bool) -> dict:
    path = app.state.db_path
    if not path:
        raise ConfigError("DB_PATH not configured")
    _ensure_db(path)
    with _open_db(path) as conn:
        conn.execute(
            "INSERT INTO backup_state (host_id, project, enabled) VALUES (?, ?, ?) "
            "ON CONFLICT(host_id, project) DO UPDATE SET enabled = excluded.enabled",
            (host_id, project, 1 if enabled else 0),
        )
        row = conn.execute(
            "SELECT enabled, cron_override, last_backup_at, last_backup_success, last_backup_message "
            "FROM backup_state WHERE host_id = ? AND project = ?",
            (host_id, project),
        ).fetchone()
    return {
        "enabled": bool(row[0]) if row else enabled,
        "cron_override": row[1] if row else None,
        "last_backup_at": _parse_timestamp(row[2]) if row else None,
        "last_backup_success": (
            None if not row or row[3] is None else bool(row[3])
        ),
        "last_backup_message": row[4] if row else None,
    }


def _set_backup_cron_override(
    host_id: str, project: str, cron_expr: Optional[str]
) -> dict:
    path = app.state.db_path
    if not path:
        raise ConfigError("DB_PATH not configured")
    _ensure_db(path)
    with _open_db(path) as conn:
        conn.execute(
            "INSERT INTO backup_state (host_id, project, cron_override) VALUES (?, ?, ?) "
            "ON CONFLICT(host_id, project) DO UPDATE SET cron_override = excluded.cron_override",
            (host_id, project, cron_expr),
        )
        row = conn.execute(
            "SELECT enabled, cron_override, last_backup_at, last_backup_success, last_backup_message "
            "FROM backup_state WHERE host_id = ? AND project = ?",
            (host_id, project),
        ).fetchone()
    return {
        "enabled": bool(row[0]) if row else False,
        "cron_override": row[1] if row else cron_expr,
        "last_backup_at": _parse_timestamp(row[2]) if row else None,
        "last_backup_success": (
            None if not row or row[3] is None else bool(row[3])
        ),
        "last_backup_message": row[4] if row else None,
    }


def _record_backup_result(
    host_id: str, project: str, success: bool, message: str
) -> None:
    path = app.state.db_path
    if not path:
        return
    _ensure_db(path)
    with _open_db(path) as conn:
        conn.execute(
            "INSERT INTO backup_state "
            "(host_id, project, enabled, last_backup_at, last_backup_success, last_backup_message) "
            "VALUES (?, ?, COALESCE((SELECT enabled FROM backup_state WHERE host_id = ? AND project = ?), 0), ?, ?, ?) "
            "ON CONFLICT(host_id, project) DO UPDATE SET "
            "last_backup_at = excluded.last_backup_at, "
            "last_backup_success = excluded.last_backup_success, "
            "last_backup_message = excluded.last_backup_message",
            (
                host_id,
                project,
                host_id,
                project,
                _now().isoformat(),
                1 if success else 0,
                message,
            ),
        )


def _record_project_state(host_id: str, project: str, path: str) -> None:
    db_path = app.state.db_path
    if not db_path:
        return
    _ensure_db(db_path)
    with _open_db(db_path) as conn:
        conn.execute(
            "INSERT INTO project_state "
            "(host_id, id, path, overall_status, updates_available, refreshed_at) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(host_id, id) DO UPDATE SET path = excluded.path",
            (host_id, project, path, None, 0, None),
        )


def _get_project_sleeping(host_id: str, project: str) -> bool:
    db_path = app.state.db_path
    if not db_path:
        return False
    _ensure_db(db_path)
    project_id = _project_id(host_id, project)
    with _open_db(db_path) as conn:
        row = conn.execute(
            "SELECT sleeping FROM project_state WHERE host_id = ? AND id = ?",
            (host_id, project_id),
        ).fetchone()
    if not row or row[0] is None:
        return False
    return bool(row[0])


def _set_project_sleeping(host_id: str, project: str, sleeping: bool) -> None:
    db_path = app.state.db_path
    if not db_path:
        return
    _ensure_db(db_path)
    project_id = _project_id(host_id, project)
    with _open_db(db_path) as conn:
        conn.execute(
            "UPDATE project_state SET sleeping = ? WHERE host_id = ? AND id = ?",
            (1 if sleeping else 0, host_id, project_id),
        )

def _open_db(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    if logger.isEnabledFor(logging.DEBUG):
        conn.set_trace_callback(lambda statement: logger.debug("SQL: %s", statement))
    return conn


def _read_setting(path: str, key: str) -> Optional[str]:
    _ensure_db(path)
    with _open_db(path) as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def _write_setting(path: str, key: str, value: Optional[str]) -> None:
    _ensure_db(path)
    with _open_db(path) as conn:
        if value is None:
            conn.execute("DELETE FROM settings WHERE key = ?", (key,))
            return
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


def _load_secret_seed() -> str:
    value = os.environ.get("SECRET_SEED", "").strip()
    if not value:
        raise ConfigError("SECRET_SEED environment variable is required.")
    return value


def _load_token_expiry() -> int:
    path = _require_db_path()
    value = _read_setting(path, "token_expiry")
    if value is None:
        _write_setting(path, "token_expiry", "300")
        return 300
    try:
        return int(value)
    except ValueError:
        _write_setting(path, "token_expiry", "300")
        return 300


def _secret_seed() -> str:
    value = getattr(app.state, "secret_seed", None)
    if value:
        return value
    app.state.secret_seed = _load_secret_seed()
    return app.state.secret_seed


def _token_expiry_seconds() -> int:
    value = getattr(app.state, "token_expiry_seconds", None)
    if value is not None:
        return int(value)
    app.state.token_expiry_seconds = _load_token_expiry()
    return app.state.token_expiry_seconds


def _get_user_password(username: str) -> Optional[str]:
    path = _require_db_path()
    with _open_db(path) as conn:
        row = conn.execute(
            "SELECT password FROM users WHERE username = ?", (username,)
        ).fetchone()
    return row[0] if row else None


def _set_token_expiry(seconds: int) -> int:
    seconds = max(30, seconds)
    path = _require_db_path()
    _write_setting(path, "token_expiry", str(seconds))
    app.state.token_expiry_seconds = seconds
    return seconds


def _load_hosts_from_db(path: str) -> Dict[str, HostConfig]:
    _ensure_db(path)
    with _open_db(path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, project_root, ssh_address, ssh_username, ssh_key, ssh_port "
            "FROM hosts"
        ).fetchall()
    hosts: Dict[str, HostConfig] = {}
    for row in rows:
        host_id = row["id"]
        if not host_id:
            continue
        host = row["ssh_address"] or ""
        user = row["ssh_username"] or ""
        project_root = row["project_root"] or ""
        ssh_key = row["ssh_key"] or ""
        if not host or not user or not project_root or not ssh_key:
            raise ConfigError(f"Host {host_id} missing required fields in DB.")
        port = row["ssh_port"] if row["ssh_port"] is not None else 22
        hosts[host_id] = HostConfig(
            host=host,
            user=user,
            ssh_key=ssh_key,
            project_root=project_root,
            port=int(port),
        )
    return hosts


def _load_backup_from_db(path: str) -> Optional[BackupConfig]:
    _ensure_db(path)
    with _open_db(path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT address, username, password, base_path, protocol, port "
            "FROM backups WHERE enabled = 1 ORDER BY id LIMIT 1"
        ).fetchone()
    if not row:
        return None
    address = row["address"] or ""
    username = row["username"] or ""
    password = row["password"] or ""
    base_path = row["base_path"] or ""
    protocol = row["protocol"] or "ssh"
    if not address or not username or not password or not base_path:
        raise ConfigError("Backup row missing required fields in DB.")
    port = row["port"] if row["port"] is not None else 22
    return BackupConfig(
        host=address,
        user=username,
        password=password,
        base_path=base_path,
        protocol=protocol,
        port=int(port),
    )


def _load_config_from_db(config: AppConfig) -> AppConfig:
    path = _db_path()
    if not path:
        return config
    hosts = _load_hosts_from_db(path)
    backup = _load_backup_from_db(path)
    return config.model_copy(update={"hosts": hosts, "backup": backup})


def _refresh_config_from_db() -> None:
    app.state.config = _load_config_from_db(app.state.config)


def _parse_timestamp(value: object) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None


def _derive_service_status(containers: List[dict]) -> str:
    if not containers:
        return "unknown"
    running_count = 0
    for container in containers:
        state = (container.get("state") or "").lower()
        status = (container.get("status") or "").lower()
        is_running = state == "running" or status.startswith("up")
        if is_running:
            running_count += 1
    if running_count == len(containers):
        return "up"
    if running_count == 0:
        return "down"
    return "degraded"


def _service_statuses_from_containers(containers: List[dict]) -> Dict[str, str]:
    grouped: Dict[str, List[dict]] = {}
    for container in containers:
        service = container.get("service") or container.get("name") or "unknown"
        grouped.setdefault(service, []).append(container)
    return {service: _derive_service_status(items) for service, items in grouped.items()}


def _derive_overall_status(statuses: List[str]) -> str:
    normalized = [status for status in statuses if status]
    if not normalized:
        return "unknown"
    if all(status == "up" for status in normalized):
        return "up"
    if all(status in ("down", "unknown") for status in normalized):
        return "down" if "down" in normalized else "unknown"
    if "degraded" in normalized:
        return "degraded"
    return "degraded"


def _project_name_from_path(path: str, fallback: str) -> str:
    if path:
        name = os.path.basename(path.rstrip("/"))
        if name:
            return name
    return fallback


def _project_id(host_id: str, project: str) -> str:
    return project


def _project_name_from_id(project_id: str, host_id: str) -> str:
    return project_id


def _is_project_running(overall: str, containers: List[dict]) -> bool:
    if overall in ("up", "degraded"):
        return True
    for container in containers:
        state = (container.get("state") or "").lower()
        status = (container.get("status") or "").lower()
        if state == "running" or status.startswith("up"):
            return True
    return False


def _backup_key(host_id: str, project: str) -> str:
    return f"{host_id}::{project}"


def _sleep_host_projects(host_id: str, host: HostConfig) -> dict:
    project_paths = compose.list_projects(host)
    stopped: List[str] = []
    skipped: List[str] = []
    ignored: List[str] = []
    errors: List[str] = []
    for path in project_paths:
        project_name = os.path.basename(path.rstrip("/"))
        _record_project_state(host_id, project_name, path)
        if _get_project_sleeping(host_id, project_name):
            skipped.append(project_name)
            continue
        try:
            overall, containers, _ = compose.project_status(host, project_name)
            if not _is_project_running(overall, containers):
                ignored.append(project_name)
                continue
            compose.stop_project(host, project_name)
            _set_project_sleeping(host_id, project_name, True)
            stopped.append(project_name)
        except Exception as exc:
            errors.append(f"{project_name}: {exc}")
    if errors:
        raise compose.ComposeError("Sleep failed: " + "; ".join(errors))
    return {
        "stopped": stopped,
        "skipped": skipped,
        "ignored": ignored,
        "total": len(project_paths),
    }


def _wake_host_projects(host_id: str, host: HostConfig) -> dict:
    project_paths = compose.list_projects(host)
    started: List[str] = []
    cleared: List[str] = []
    skipped: List[str] = []
    errors: List[str] = []
    for path in project_paths:
        project_name = os.path.basename(path.rstrip("/"))
        _record_project_state(host_id, project_name, path)
        if not _get_project_sleeping(host_id, project_name):
            skipped.append(project_name)
            continue
        try:
            overall, containers, _ = compose.project_status(host, project_name)
            if _is_project_running(overall, containers):
                _set_project_sleeping(host_id, project_name, False)
                cleared.append(project_name)
                continue
            compose.start_project(host, project_name)
            _set_project_sleeping(host_id, project_name, False)
            started.append(project_name)
        except Exception as exc:
            errors.append(f"{project_name}: {exc}")
    if errors:
        raise compose.ComposeError("Wake failed: " + "; ".join(errors))
    return {
        "started": started,
        "cleared": cleared,
        "skipped": skipped,
        "total": len(project_paths),
    }


async def _register_backup_control(host_id: str, project: str) -> threading.Event:
    key = _backup_key(host_id, project)
    async with app.state.backup_lock:
        stop_event = threading.Event()
        app.state.backup_controls[key] = stop_event
        return stop_event


async def _clear_backup_control(host_id: str, project: str) -> None:
    key = _backup_key(host_id, project)
    async with app.state.backup_lock:
        app.state.backup_controls.pop(key, None)


async def _request_backup_stop(host_id: str, project: str) -> bool:
    key = _backup_key(host_id, project)
    async with app.state.backup_lock:
        stop_event = app.state.backup_controls.get(key)
        if not stop_event:
            return False
        stop_event.set()
        return True


async def _backup_in_progress(host_id: str, project: str) -> bool:
    key = _backup_key(host_id, project)
    async with app.state.backup_lock:
        return key in app.state.backup_controls


def _action_key(host_id: str, project: str, action: str) -> str:
    return f"{host_id}::{project}::{action}"


def _service_action_key(host_id: str, project: str, service: str, action: str) -> str:
    return f"{host_id}::{project}::{service}::{action}"


async def _register_action_control(
    host_id: str, project: str, action: str
) -> threading.Event:
    key = _action_key(host_id, project, action)
    async with app.state.action_lock:
        if key in app.state.action_controls:
            raise HTTPException(status_code=409, detail="Action already running")
        stop_event = threading.Event()
        app.state.action_controls[key] = stop_event
        return stop_event


async def _clear_action_control(host_id: str, project: str, action: str) -> None:
    key = _action_key(host_id, project, action)
    async with app.state.action_lock:
        app.state.action_controls.pop(key, None)


async def _request_action_stop(host_id: str, project: str, action: str) -> bool:
    key = _action_key(host_id, project, action)
    async with app.state.action_lock:
        stop_event = app.state.action_controls.get(key)
        if not stop_event:
            return False
        stop_event.set()
        return True


async def _register_service_action_control(
    host_id: str, project: str, service: str, action: str
) -> threading.Event:
    key = _service_action_key(host_id, project, service, action)
    async with app.state.action_lock:
        if key in app.state.action_controls:
            raise HTTPException(status_code=409, detail="Action already running")
        stop_event = threading.Event()
        app.state.action_controls[key] = stop_event
        return stop_event


async def _clear_service_action_control(
    host_id: str, project: str, service: str, action: str
) -> None:
    key = _service_action_key(host_id, project, service, action)
    async with app.state.action_lock:
        app.state.action_controls.pop(key, None)


async def _request_service_action_stop(
    host_id: str, project: str, service: str, action: str
) -> bool:
    key = _service_action_key(host_id, project, service, action)
    async with app.state.action_lock:
        stop_event = app.state.action_controls.get(key)
        if not stop_event:
            return False
        stop_event.set()
        return True


def _load_state_from_db(host_id: Optional[str] = None) -> dict:
    path = app.state.db_path
    if not path:
        return {"refreshed_at": None, "hosts": []}
    _ensure_db(path)
    with _open_db(path) as conn:
        conn.row_factory = sqlite3.Row
        if host_id:
            project_rows = conn.execute(
                "SELECT host_id, id, path, overall_status, updates_available, sleeping, refreshed_at "
                "FROM project_state WHERE host_id = ?",
                (host_id,),
            ).fetchall()
        else:
            project_rows = conn.execute(
                "SELECT host_id, id, path, overall_status, updates_available, sleeping, refreshed_at "
                "FROM project_state"
            ).fetchall()

        services_by_project: Dict[tuple[str, str], List[dict]] = {}
        if host_id:
            service_rows = conn.execute(
                "SELECT host_id, project_id, id, status, update_available, update_checked_at, refreshed_at "
                "FROM service_state WHERE host_id = ?",
                (host_id,),
            ).fetchall()
        else:
            service_rows = conn.execute(
                "SELECT host_id, project_id, id, status, update_available, update_checked_at, refreshed_at "
                "FROM service_state"
            ).fetchall()
        for row in service_rows:
            services_by_project.setdefault(
                (row["host_id"], row["project_id"]), []
            ).append(
                {
                    "id": row["id"],
                    "status": row["status"],
                    "update_available": bool(row["update_available"]),
                    "update_checked_at": _parse_timestamp(row["update_checked_at"]),
                    "refreshed_at": _parse_timestamp(row["refreshed_at"]),
                }
            )

        if host_id:
            backup_rows = conn.execute(
                "SELECT host_id, project, enabled, last_backup_at, last_backup_success, last_backup_message "
                "FROM backup_state WHERE host_id = ?",
                (host_id,),
            ).fetchall()
        else:
            backup_rows = conn.execute(
                "SELECT host_id, project, enabled, last_backup_at, last_backup_success, last_backup_message "
                "FROM backup_state"
            ).fetchall()
        backup_map = {}
        for row in backup_rows:
            backup_map[(row["host_id"], row["project"])] = {
                "enabled": bool(row["enabled"]),
                "last_backup_at": _parse_timestamp(row["last_backup_at"]),
                "last_backup_success": (
                    None
                    if row["last_backup_success"] is None
                    else bool(row["last_backup_success"])
                ),
                "last_backup_message": row["last_backup_message"],
            }

        host_map: Dict[str, dict] = {}
        overall_refreshed: Optional[datetime] = None
        for row in project_rows:
            proj_refreshed = _parse_timestamp(row["refreshed_at"])
            if proj_refreshed and (
                overall_refreshed is None or proj_refreshed > overall_refreshed
            ):
                overall_refreshed = proj_refreshed
            host_entry = host_map.setdefault(
                row["host_id"], {"host_id": row["host_id"], "projects": []}
            )
            project_name = _project_name_from_path(row["path"], row["id"])
            backup_info = backup_map.get((row["host_id"], project_name), {})
            host_entry["projects"].append(
                {
                    "project": project_name,
                    "path": row["path"],
                    "overall_status": row["overall_status"],
                    "updates_available": bool(row["updates_available"]),
                    "sleeping": bool(row["sleeping"]),
                    "refreshed_at": proj_refreshed,
                    "backup_enabled": backup_info.get("enabled", False),
                    "last_backup_at": backup_info.get("last_backup_at"),
                    "last_backup_success": backup_info.get("last_backup_success"),
                    "last_backup_message": backup_info.get("last_backup_message"),
                    "services": sorted(
                        services_by_project.get((row["host_id"], row["id"]), []),
                        key=lambda item: item["id"],
                    ),
                }
            )

        for host_entry in host_map.values():
            host_projects = host_entry.get("projects", [])
            refreshed = None
            for project in host_projects:
                proj_refreshed = project.get("refreshed_at")
                if proj_refreshed and (refreshed is None or proj_refreshed > refreshed):
                    refreshed = proj_refreshed
            host_entry["refreshed_at"] = refreshed
            host_entry["projects"] = sorted(
                host_projects, key=lambda item: item["project"]
            )

        hosts = sorted(host_map.values(), key=lambda item: item["host_id"])
        return {"refreshed_at": overall_refreshed, "hosts": hosts}


def _persist_state_snapshot(
    hosts_data: dict,
    include_status: bool,
    include_updates: bool,
    refreshed_at: datetime,
) -> None:
    path = app.state.db_path
    if not path:
        return
    _ensure_db(path)
    refreshed_at_str = refreshed_at.isoformat()
    with _open_db(path) as conn:
        for host_id, data in hosts_data.items():
            project_list_failed = data.pop("_project_list_failed", False)
            if project_list_failed:
                continue
            projects = data.get("projects", [])
            project_ids = [
                _project_id(host_id, project["project"])
                for project in projects
                if project.get("project")
            ]
            if project_ids:
                placeholders = ",".join(["?"] * len(project_ids))
                conn.execute(
                    f"DELETE FROM project_state WHERE host_id = ? AND id NOT IN ({placeholders})",
                    (host_id, *project_ids),
                )
            else:
                conn.execute("DELETE FROM project_state WHERE host_id = ?", (host_id,))

            for project in projects:
                project_name = project.get("project")
                if not project_name:
                    continue
                project_id = _project_id(host_id, project_name)
                project_path = project.get("path") or ""
                conn.execute(
                    "INSERT INTO project_state "
                    "(host_id, id, path, overall_status, updates_available, refreshed_at) "
                    "VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(host_id, id) DO UPDATE SET path = excluded.path",
                    (host_id, project_id, project_path, None, 0, None),
                )
                conn.execute(
                    "INSERT INTO backup_state (host_id, project, enabled) VALUES (?, ?, 0) "
                    "ON CONFLICT(host_id, project) DO NOTHING",
                    (host_id, project_name),
                )

                status_ok = project.get("status_ok", False)
                updates_ok = project.get("updates_ok", False)
                service_statuses = project.get("service_statuses") if status_ok else {}
                service_updates = project.get("service_updates") if updates_ok else {}
                service_ids = set(service_statuses) | set(service_updates)
                for service_id in service_ids:
                    status = service_statuses.get(service_id) if include_status else None
                    update_available = None
                    if include_updates and service_id in service_updates:
                        update_available = 1 if service_updates[service_id] else 0
                    service_refreshed = (
                        refreshed_at_str if include_status and status is not None else None
                    )
                    conn.execute(
                        "INSERT INTO service_state "
                        "(host_id, project_id, id, status, update_available, refreshed_at) "
                        "VALUES (?, ?, ?, ?, ?, ?) "
                        "ON CONFLICT(host_id, project_id, id) DO UPDATE SET "
                        "status = COALESCE(excluded.status, service_state.status), "
                        "update_available = COALESCE(excluded.update_available, service_state.update_available), "
                        "refreshed_at = COALESCE(excluded.refreshed_at, service_state.refreshed_at)",
                        (
                            host_id,
                            project_id,
                            service_id,
                            status,
                            update_available,
                            service_refreshed,
                        ),
                    )

                if include_status and status_ok:
                    service_list = list(service_statuses.keys())
                    if service_list:
                        placeholders = ",".join(["?"] * len(service_list))
                        conn.execute(
                            f"DELETE FROM service_state WHERE host_id = ? AND project_id = ? AND id NOT IN ({placeholders})",
                            (host_id, project_id, *service_list),
                        )
                    else:
                        conn.execute(
                            "DELETE FROM service_state WHERE host_id = ? AND project_id = ?",
                            (host_id, project_id),
                        )

                rows = conn.execute(
                    "SELECT status, update_available, refreshed_at FROM service_state "
                    "WHERE host_id = ? AND project_id = ?",
                    (host_id, project_id),
                ).fetchall()
                statuses = [row[0] for row in rows if row[0]]
                updates_available = any(bool(row[1]) for row in rows)
                refreshed_values = [_parse_timestamp(row[2]) for row in rows if row[2]]
                project_refreshed = None
                for value in refreshed_values:
                    if value and (project_refreshed is None or value > project_refreshed):
                        project_refreshed = value
                if project_refreshed is None and include_status and status_ok:
                    project_refreshed = refreshed_at
                if include_status and status_ok and not statuses:
                    overall_status = "down"
                else:
                    overall_status = _derive_overall_status(statuses)
                conn.execute(
                    "UPDATE project_state SET overall_status = ?, updates_available = ?, "
                    "refreshed_at = COALESCE(?, refreshed_at) "
                    "WHERE host_id = ? AND id = ?",
                    (
                        overall_status,
                        1 if updates_available else 0,
                        project_refreshed.isoformat() if project_refreshed else None,
                        host_id,
                        project_id,
                    ),
                )


def _select_update_candidate(host_ids: Optional[List[str]]) -> Optional[dict]:
    path = app.state.db_path
    if not path:
        return None
    _ensure_db(path)
    with _open_db(path) as conn:
        conn.row_factory = sqlite3.Row
        params: List[str] = []
        where_clause = "WHERE project_state.updates_available = 0"
        if host_ids:
            placeholders = ",".join(["?"] * len(host_ids))
            where_clause = (
                "WHERE project_state.updates_available = 0 AND "
                f"project_state.host_id IN ({placeholders})"
            )
            params = list(host_ids)
        row = conn.execute(
            "SELECT project_state.host_id, project_state.id AS project_id, project_state.path, "
            "service_state.id AS service_id, service_state.update_checked_at "
            "FROM service_state "
            "JOIN project_state ON project_state.host_id = service_state.host_id "
            "AND project_state.id = service_state.project_id "
            f"{where_clause} "
            "ORDER BY service_state.update_checked_at IS NOT NULL, service_state.update_checked_at ASC "
            "LIMIT 1",
            params,
        ).fetchone()
        if row:
            return dict(row)

        project_params: List[str] = []
        project_where = "AND project_state.updates_available = 0"
        if host_ids:
            placeholders = ",".join(["?"] * len(host_ids))
            project_where = (
                "AND project_state.updates_available = 0 AND "
                f"project_state.host_id IN ({placeholders})"
            )
            project_params = list(host_ids)
        row = conn.execute(
            "SELECT project_state.host_id, project_state.id AS project_id, project_state.path "
            "FROM project_state "
            "LEFT JOIN service_state ON service_state.host_id = project_state.host_id "
            "AND service_state.project_id = project_state.id "
            "WHERE service_state.project_id IS NULL "
            f"{project_where} "
            "ORDER BY project_state.refreshed_at IS NOT NULL, project_state.refreshed_at ASC "
            "LIMIT 1",
            project_params,
        ).fetchone()
        if row:
            return dict(row)
    return None


def _select_status_candidate(host_ids: Optional[List[str]]) -> Optional[dict]:
    path = app.state.db_path
    if not path:
        return None
    if host_ids is not None and not host_ids:
        return None
    _ensure_db(path)
    with _open_db(path) as conn:
        conn.row_factory = sqlite3.Row
        params: List[str] = []
        where_clause = ""
        if host_ids:
            placeholders = ",".join(["?"] * len(host_ids))
            where_clause = f"WHERE host_id IN ({placeholders})"
            params = list(host_ids)
        row = conn.execute(
            "SELECT host_id, id AS project_id, path, refreshed_at "
            "FROM project_state "
            f"{where_clause} "
            "ORDER BY refreshed_at IS NOT NULL, refreshed_at ASC "
            "LIMIT 1",
            params,
        ).fetchone()
        if row:
            return dict(row)
    return None


def _select_project_service_candidate(host_id: str, project_id: str) -> Optional[str]:
    path = app.state.db_path
    if not path:
        return None
    _ensure_db(path)
    with _open_db(path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT service_state.id AS service_id, service_state.update_checked_at "
            "FROM service_state "
            "WHERE service_state.host_id = ? AND service_state.project_id = ? "
            "ORDER BY service_state.update_checked_at IS NOT NULL, service_state.update_checked_at ASC "
            "LIMIT 1",
            (host_id, project_id),
        ).fetchone()
        if row:
            return row["service_id"]
    return None


def _sync_project_services(host_id: str, project_id: str, service_ids: List[str]) -> None:
    path = app.state.db_path
    if not path:
        return
    _ensure_db(path)
    with _open_db(path) as conn:
        if service_ids:
            for service_id in service_ids:
                conn.execute(
                    "INSERT INTO service_state (host_id, project_id, id) VALUES (?, ?, ?) "
                    "ON CONFLICT(host_id, project_id, id) DO NOTHING",
                    (host_id, project_id, service_id),
                )
            placeholders = ",".join(["?"] * len(service_ids))
            conn.execute(
                f"DELETE FROM service_state WHERE host_id = ? AND project_id = ? AND id NOT IN ({placeholders})",
                (host_id, project_id, *service_ids),
            )
        else:
            conn.execute(
                "DELETE FROM service_state WHERE host_id = ? AND project_id = ?",
                (host_id, project_id),
            )


def _update_service_update_state(
    host_id: str,
    project_id: str,
    service_id: str,
    update_available: Optional[bool],
    checked_at: datetime,
) -> None:
    path = app.state.db_path
    if not path:
        return
    _ensure_db(path)
    with _open_db(path) as conn:
        if update_available is None:
            conn.execute(
                "INSERT INTO service_state (host_id, project_id, id) VALUES (?, ?, ?) "
                "ON CONFLICT(host_id, project_id, id) DO NOTHING",
                (host_id, project_id, service_id),
            )
        else:
            conn.execute(
                "INSERT INTO service_state (host_id, project_id, id, update_available, update_checked_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(host_id, project_id, id) DO UPDATE SET "
                "update_available = excluded.update_available, "
                "update_checked_at = excluded.update_checked_at",
                (
                    host_id,
                    project_id,
                    service_id,
                    1 if update_available else 0,
                    checked_at.isoformat(),
                ),
            )

        if update_available is None:
            conn.execute(
                "UPDATE service_state SET update_checked_at = ? "
                "WHERE host_id = ? AND project_id = ? AND id = ?",
                (checked_at.isoformat(), host_id, project_id, service_id),
            )

        rows = conn.execute(
            "SELECT status, update_available, refreshed_at FROM service_state "
            "WHERE host_id = ? AND project_id = ?",
            (host_id, project_id),
        ).fetchall()
        statuses = [row[0] for row in rows if row[0]]
        updates_available = any(bool(row[1]) for row in rows)
        refreshed_values = [_parse_timestamp(row[2]) for row in rows if row[2]]
        project_refreshed = None
        for value in refreshed_values:
            if value and (project_refreshed is None or value > project_refreshed):
                project_refreshed = value
        overall_status = _derive_overall_status(statuses)
        conn.execute(
            "UPDATE project_state SET overall_status = ?, updates_available = ?, refreshed_at = ? "
            "WHERE host_id = ? AND id = ?",
            (
                overall_status,
                1 if updates_available else 0,
                project_refreshed.isoformat() if project_refreshed else None,
                host_id,
                project_id,
            ),
        )


def _mark_project_updates_current(
    host_id: str, project: str, checked_at: datetime
) -> None:
    path = app.state.db_path
    if not path:
        return
    _ensure_db(path)
    project_id = _project_id(host_id, project)
    with _open_db(path) as conn:
        conn.execute(
            "UPDATE service_state SET update_available = 0, update_checked_at = ? "
            "WHERE host_id = ? AND project_id = ?",
            (checked_at.isoformat(), host_id, project_id),
        )
        conn.execute(
            "UPDATE project_state SET updates_available = 0 WHERE host_id = ? AND id = ?",
            (host_id, project_id),
        )


def _update_project_status_state(
    host_id: str,
    project_id: str,
    service_statuses: Dict[str, str],
    refreshed_at: datetime,
    overall_status: Optional[str] = None,
) -> None:
    path = app.state.db_path
    if not path:
        return
    _ensure_db(path)
    refreshed_at_str = refreshed_at.isoformat()
    with _open_db(path) as conn:
        service_ids = list(service_statuses.keys())
        if service_ids:
            for service_id, status in service_statuses.items():
                conn.execute(
                    "INSERT INTO service_state (host_id, project_id, id, status, refreshed_at) "
                    "VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT(host_id, project_id, id) DO UPDATE SET "
                    "status = excluded.status, "
                    "refreshed_at = excluded.refreshed_at",
                    (host_id, project_id, service_id, status, refreshed_at_str),
                )
            placeholders = ",".join(["?"] * len(service_ids))
            conn.execute(
                f"DELETE FROM service_state WHERE host_id = ? AND project_id = ? AND id NOT IN ({placeholders})",
                (host_id, project_id, *service_ids),
            )
        else:
            conn.execute(
                "DELETE FROM service_state WHERE host_id = ? AND project_id = ?",
                (host_id, project_id),
            )

        rows = conn.execute(
            "SELECT status, update_available, refreshed_at FROM service_state "
            "WHERE host_id = ? AND project_id = ?",
            (host_id, project_id),
        ).fetchall()
        statuses = [row[0] for row in rows if row[0]]
        updates_available = any(bool(row[1]) for row in rows)
        refreshed_values = [_parse_timestamp(row[2]) for row in rows if row[2]]
        project_refreshed = None
        for value in refreshed_values:
            if value and (project_refreshed is None or value > project_refreshed):
                project_refreshed = value
        if project_refreshed is None:
            project_refreshed = refreshed_at
        derived_status = _derive_overall_status(statuses)
        if derived_status == "unknown" and overall_status:
            derived_status = overall_status
        conn.execute(
            "UPDATE project_state SET overall_status = ?, updates_available = ?, refreshed_at = ? "
            "WHERE host_id = ? AND id = ?",
            (
                derived_status,
                1 if updates_available else 0,
                project_refreshed.isoformat(),
                host_id,
                project_id,
            ),
        )


def _touch_project_status_refreshed(
    host_id: str, project_id: str, refreshed_at: datetime
) -> None:
    path = app.state.db_path
    if not path:
        return
    _ensure_db(path)
    with _open_db(path) as conn:
        conn.execute(
            "UPDATE project_state SET refreshed_at = ? WHERE host_id = ? AND id = ?",
            (refreshed_at.isoformat(), host_id, project_id),
        )


def _update_slot_available(window_seconds: int = 3600, max_requests: int = 5) -> bool:
    count, _ = _read_update_window(window_seconds)
    return count < max_requests


def _read_update_window(window_seconds: int) -> tuple[int, Optional[str]]:
    path = app.state.db_path
    if not path:
        return 0, None
    _ensure_db(path)
    threshold = (_now() - timedelta(seconds=window_seconds)).isoformat()
    with _open_db(path) as conn:
        row = conn.execute(
            "SELECT COUNT(update_checked_at), MIN(update_checked_at) "
            "FROM service_state "
            "WHERE update_checked_at IS NOT NULL AND update_checked_at >= ?",
            (threshold,),
        ).fetchone()
    if not row:
        return 0, None
    return int(row[0] or 0), row[1]


def _start_state_task() -> Optional[asyncio.Task]:
    if app.state.state_interval_seconds <= 0:
        return None
    return asyncio.create_task(_state_refresh_loop())


def _start_update_task() -> Optional[asyncio.Task]:
    if app.state.update_interval_seconds <= 0:
        return None
    return asyncio.create_task(_update_refresh_loop())


def _start_backup_task() -> Optional[asyncio.Task]:
    if not _config().backup:
        return None
    if not app.state.db_path:
        return None
    return asyncio.create_task(_backup_refresh_loop())


def _start_token_cleanup_task() -> Optional[asyncio.Task]:
    if not app.state.db_path:
        return None
    return asyncio.create_task(_token_cleanup_loop())


def _restart_backup_task() -> None:
    def _restart() -> None:
        task = getattr(app.state, "backup_task", None)
        if task:
            task.cancel()
        app.state.backup_task = _start_backup_task()

    try:
        asyncio.get_running_loop()
        _restart()
        return
    except RuntimeError:
        pass

    loop = getattr(app.state, "loop", None)
    if loop and loop.is_running():
        loop.call_soon_threadsafe(_restart)
        return
    logger.warning("Backup task restart skipped: no running event loop.")


async def _stop_state_task() -> None:
    task = getattr(app.state, "state_task", None)
    if not task:
        return
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


async def _stop_update_task() -> None:
    task = getattr(app.state, "update_task", None)
    if not task:
        return
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


async def _stop_backup_task() -> None:
    task = getattr(app.state, "backup_task", None)
    if not task:
        return
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


def _purge_expired_tokens() -> None:
    path = app.state.db_path
    if not path:
        return
    _ensure_db(path)
    now = _now().isoformat()
    with _open_db(path) as conn:
        conn.execute(
            "DELETE FROM tokens WHERE expiration IS NOT NULL AND expiration < ?",
            (now,),
        )


async def _token_cleanup_loop() -> None:
    while True:
        try:
            await asyncio.to_thread(_purge_expired_tokens)
        except Exception:
            logger.exception("Token cleanup failed")
        await asyncio.sleep(TOKEN_CLEANUP_INTERVAL_SECONDS)


async def _set_state_interval(seconds: int) -> None:
    await _stop_state_task()
    app.state.state_interval_seconds = max(0, seconds)
    app.state.state_task = _start_state_task()
    _persist_interval_setting("state_interval_seconds", app.state.state_interval_seconds)


async def _set_update_interval(seconds: int) -> None:
    await _stop_update_task()
    app.state.update_interval_seconds = max(0, seconds)
    app.state.update_task = _start_update_task()
    _persist_interval_setting("update_interval_seconds", app.state.update_interval_seconds)


def _select_hosts(config: AppConfig, host_ids: Optional[List[str]]) -> dict:
    if host_ids is None:
        return config.hosts
    selected = {}
    for host_id in host_ids:
        host = config.hosts.get(host_id)
        if not host:
            raise ConfigError(f"Unknown host id: {host_id}")
        selected[host_id] = host
    return selected


def _build_state_snapshot(
    config: AppConfig,
    host_ids: Optional[List[str]],
    include_status: bool = True,
    include_updates: bool = True,
) -> tuple[datetime, dict]:
    now = _now()
    hosts_data = {}
    for host_id, host in _select_hosts(config, host_ids).items():
        projects = []
        try:
            project_paths = compose.list_projects(host)
        except Exception as exc:
            hosts_data[host_id] = {
                "host_id": host_id,
                "projects": [],
                "errors": [str(exc)],
                "_project_list_failed": True,
            }
            continue

        project_names = [os.path.basename(path.rstrip("/")) for path in project_paths]
        for project_name, project_path in zip(project_names, project_paths):
            service_statuses: Dict[str, str] = {}
            service_updates: Dict[str, bool] = {}
            status_ok = False
            updates_ok = False
            if include_status:
                try:
                    _, containers, _ = compose.project_status(host, project_name)
                    service_statuses = _service_statuses_from_containers(containers)
                    status_ok = True
                except Exception:
                    status_ok = False
            if include_updates:
                updates_ok = False

            projects.append(
                {
                    "project": project_name,
                    "path": project_path,
                    "service_statuses": service_statuses,
                    "service_updates": service_updates,
                    "status_ok": status_ok,
                    "updates_ok": updates_ok,
                }
            )

        hosts_data[host_id] = {
            "host_id": host_id,
            "projects": projects,
            "_project_list_failed": False,
        }

    return now, hosts_data

async def _apply_state_snapshot(
    hosts_data: dict,
    include_status: bool,
    include_updates: bool,
    refreshed_at: datetime,
) -> None:
    async with app.state.state_lock:
        await asyncio.to_thread(
            _persist_state_snapshot, hosts_data, include_status, include_updates, refreshed_at
        )


async def _refresh_state(host_ids: Optional[List[str]] = None) -> datetime:
    now = await _refresh_status_state(host_ids)
    await _refresh_update_state(host_ids)
    return now


async def _refresh_project_list(host_ids: Optional[List[str]] = None) -> datetime:
    config = _config()
    now, hosts_data = await asyncio.to_thread(
        _build_state_snapshot, config, host_ids, False, False
    )
    await _apply_state_snapshot(hosts_data, False, False, now)
    return now


async def _refresh_status_state(host_ids: Optional[List[str]] = None) -> datetime:
    config = _config()
    now, hosts_data = await asyncio.to_thread(
        _build_state_snapshot, config, host_ids, True, False
    )
    await _apply_state_snapshot(hosts_data, True, False, now)
    logger.info("Status state refreshed")
    return now


async def _refresh_status_candidate(
    host_ids: Optional[List[str]] = None,
) -> datetime:
    await _refresh_project_list(host_ids)
    async with app.state.state_lock:
        candidate = await asyncio.to_thread(_select_status_candidate, host_ids)
    if not candidate:
        return _now()

    host_id = candidate["host_id"]
    project_id = candidate["project_id"]
    project_path = candidate.get("path") or ""
    host = _host(host_id)
    project_name = _project_name_from_path(
        project_path, _project_name_from_id(project_id, host_id)
    )
    try:
        overall, containers, _ = await asyncio.to_thread(
            compose.project_status, host, project_name
        )
        service_statuses = _service_statuses_from_containers(containers)
        async with app.state.state_lock:
            await asyncio.to_thread(
                _update_project_status_state,
                host_id,
                project_id,
                service_statuses,
                _now(),
                overall,
            )
        logger.info("Status refreshed host=%s project=%s", host_id, project_name)
    except Exception:
        async with app.state.state_lock:
            await asyncio.to_thread(
                _touch_project_status_refreshed, host_id, project_id, _now()
            )
        logger.exception(
            "Status refresh failed host=%s project=%s", host_id, project_name
        )
    return _now()


async def _refresh_update_state(host_ids: Optional[List[str]] = None) -> datetime:
    now = _now()
    if not compose.UPDATE_CHECKS_ENABLED:
        return now
    async with app.state.state_lock:
        candidate = await asyncio.to_thread(_select_update_candidate, host_ids)
    if not candidate:
        return now

    host_id = candidate["host_id"]
    project_id = candidate["project_id"]
    project_path = candidate.get("path") or ""
    host = _host(host_id)
    project_name = _project_name_from_path(
        project_path, _project_name_from_id(project_id, host_id)
    )

    try:
        service_images = await asyncio.to_thread(
            compose.list_service_images, host, project_name
        )
    except Exception:
        return now

    async with app.state.state_lock:
        await asyncio.to_thread(
            _sync_project_services, host_id, project_id, list(service_images.keys())
        )

        service_id = candidate.get("service_id")
        if not service_id or service_id not in service_images:
            service_id = await asyncio.to_thread(
                _select_project_service_candidate, host_id, project_id
            )
    if not service_id or service_id not in service_images:
        return now

    async with app.state.state_lock:
        allowed = await asyncio.to_thread(_update_slot_available)
    if not allowed:
        logger.info("Update check skipped due to rate limit")
        return now
    update_available = await asyncio.to_thread(
        compose.check_image_update, host, service_images[service_id]
    )
    async with app.state.state_lock:
        await asyncio.to_thread(
            _update_service_update_state,
            host_id,
            project_id,
            service_id,
            update_available,
            now,
        )
    logger.info(
        "Update check complete host=%s project=%s service=%s update=%s",
        host_id,
        project_name,
        service_id,
        update_available,
    )
    return now


async def _refresh_project_state(host_id: str, project: str) -> datetime:
    host = _host(host_id)
    try:
        project_paths = await asyncio.to_thread(compose.list_projects, host)
    except Exception as exc:
        _handle_errors(exc)
    projects = [os.path.basename(path.rstrip("/")) for path in project_paths]
    if project not in projects:
        raise HTTPException(status_code=404, detail="Unknown project.")
    path_map = {name: path for name, path in zip(projects, project_paths)}
    project_path = path_map.get(project, "")
    await asyncio.to_thread(_record_project_state, host_id, project, project_path)
    await asyncio.to_thread(_ensure_backup_entries, host_id, [project])

    project_id = _project_id(host_id, project)
    try:
        overall, containers, _ = await asyncio.to_thread(
            compose.project_status, host, project
        )
        service_statuses = _service_statuses_from_containers(containers)
        async with app.state.state_lock:
            await asyncio.to_thread(
                _update_project_status_state,
                host_id,
                project_id,
                service_statuses,
                _now(),
                overall,
            )
    except Exception as exc:
        async with app.state.state_lock:
            await asyncio.to_thread(
                _touch_project_status_refreshed, host_id, project_id, _now()
            )
        _handle_errors(exc)
    return _now()


def _load_enabled_backups() -> List[dict]:
    path = app.state.db_path
    if not path:
        return []
    _ensure_db(path)
    with _open_db(path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT host_id, project, cron_override, last_backup_at "
            "FROM backup_state WHERE enabled = 1"
        ).fetchall()
    items = []
    for row in rows:
        items.append(
            {
                "host_id": row["host_id"],
                "project": row["project"],
                "cron_override": row["cron_override"],
                "last_backup_at": _parse_timestamp(row["last_backup_at"]),
            }
        )
    return items


async def _run_scheduled_backup_for_project(host_id: str, project: str) -> None:
    backup = _backup_config()
    if await _backup_in_progress(host_id, project):
        logger.info(
            "Skipping scheduled backup (already running) host=%s project=%s",
            host_id,
            project,
        )
        return
    host = _host(host_id)
    try:
        dest, output = await asyncio.to_thread(
            _backup_with_restart, host_id, host, project, backup
        )
        message = output or dest or "Backup complete"
        await asyncio.to_thread(
            _record_backup_result, host_id, project, True, message
        )
        logger.info(
            "Scheduled backup complete host=%s project=%s",
            host_id,
            project,
        )
    except Exception as exc:
        await asyncio.to_thread(
            _record_backup_result, host_id, project, False, str(exc)
        )
        logger.exception(
            "Scheduled backup failed host=%s project=%s",
            host_id,
            project,
        )


async def _backup_refresh_loop() -> None:
    schedule_event = app.state.backup_schedule_event
    while True:
        try:
            now = _now()
            cron_expr = await asyncio.to_thread(_load_backup_cron)
            enabled = await asyncio.to_thread(_load_enabled_backups)
            schedule_map = app.state.backup_schedule_map
            active_keys = set()
            for item in enabled:
                cron_value = item["cron_override"] or cron_expr
                if not cron_value:
                    continue
                key = _backup_key(item["host_id"], item["project"])
                active_keys.add(key)
                existing = schedule_map.get(key)
                if not existing or existing.get("cron") != cron_value or not existing.get("next_run"):
                    base = item["last_backup_at"] or now
                    next_run = _next_cron_run(cron_value, base)
                    schedule_map[key] = {"cron": cron_value, "next_run": next_run}

            for key in list(schedule_map.keys()):
                if key not in active_keys:
                    schedule_map.pop(key, None)

            if not schedule_map:
                schedule_event.clear()
                try:
                    await asyncio.wait_for(schedule_event.wait(), timeout=60)
                except asyncio.TimeoutError:
                    pass
                continue

            ran_any = False
            for key, entry in list(schedule_map.items()):
                next_run = entry.get("next_run")
                if not next_run or next_run > now:
                    continue
                host_id, project = key.split("::", 1)
                await _run_scheduled_backup_for_project(host_id, project)
                ran_any = True
                cron_value = entry.get("cron")
                schedule_map[key]["next_run"] = (
                    _next_cron_run(cron_value, _now()) if cron_value else None
                )

            next_times = [
                entry.get("next_run")
                for entry in schedule_map.values()
                if entry.get("next_run")
            ]
            if not next_times:
                await asyncio.sleep(60)
                continue
            next_run = min(next_times)
            sleep_seconds = max(30, (next_run - _now()).total_seconds())
            schedule_event.clear()
            try:
                await asyncio.wait_for(schedule_event.wait(), timeout=sleep_seconds)
            except asyncio.TimeoutError:
                pass
        except HTTPException:
            raise
        except Exception:
            logger.exception("Scheduled backup run failed")
        await asyncio.sleep(60)


async def _state_refresh_loop() -> None:
    interval = app.state.state_interval_seconds
    if interval <= 0:
        return
    while True:
        try:
            await _refresh_status_candidate()
        except Exception:
            logger.exception("Status state refresh failed")
            pass
        await asyncio.sleep(interval)


async def _update_refresh_loop() -> None:
    interval = app.state.update_interval_seconds
    if interval <= 0:
        return
    while True:
        try:
            await _refresh_update_state()
        except Exception:
            logger.exception("Update state refresh failed")
            pass
        await asyncio.sleep(interval)




def _config() -> AppConfig:
    return app.state.config


def _host(host_id: str):
    try:
        return get_host_config(_config(), host_id)
    except ConfigError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


def _backup_config():
    backup = _config().backup
    if not backup:
        raise HTTPException(status_code=400, detail="Backup configuration missing.")
    return backup


def _handle_errors(exc: Exception) -> None:
    if isinstance(exc, (compose.ComposeError, SSHError)):
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    raise exc


def _backup_with_restart(host_id: str, host, project: str, backup) -> tuple[str, str]:
    output_lines: List[str] = []
    running = False
    dest = ""
    try:
        overall, containers, _ = compose.project_status(host, project)
        running = _is_project_running(overall, containers)
        if running:
            output_lines.append("Stopping project")
            stop_result = compose.stop_project(host, project)
            if stop_result.stdout:
                output_lines.append(stop_result.stdout.strip())

        output_lines.append("Running backup")
        dest, output = compose.backup_project(host_id, host, project, backup)
        if dest:
            output_lines.append(f"Backup destination: {dest}")
        if output:
            output_lines.append(output.strip())
    except Exception as exc:
        output_lines.append(f"Backup failed: {exc}")
        raise
    finally:
        if running:
            output_lines.append("Starting project")
            try:
                start_result = compose.start_project(host, project)
                if start_result.stdout:
                    output_lines.append(start_result.stdout.strip())
            except Exception as start_exc:
                output_lines.append(f"Start failed: {start_exc}")

    return dest, "\n".join([line for line in output_lines if line])


def _sse_event(event: str, payload: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(payload)}\n\n"


@app.get("/config/hosts", response_model=List[HostConfigEntry])
def list_host_configs() -> List[HostConfigEntry]:
    path = _require_db_path()
    with _open_db(path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, project_root, ssh_address, ssh_username, ssh_key, ssh_port "
            "FROM hosts ORDER BY id"
        ).fetchall()
    entries = []
    for row in rows:
        entries.append(
            HostConfigEntry(
                id=row["id"],
                project_root=row["project_root"] or "",
                ssh_address=row["ssh_address"] or "",
                ssh_username=row["ssh_username"] or "",
                ssh_key=row["ssh_key"] or "",
                ssh_port=int(row["ssh_port"] or 22),
            )
        )
    return entries


@app.post("/config/hosts", response_model=HostConfigEntry, status_code=201)
def create_host_config(entry: HostConfigEntry) -> HostConfigEntry:
    if not entry.id.strip():
        raise HTTPException(status_code=400, detail="Host id is required.")
    if not entry.project_root.strip():
        raise HTTPException(status_code=400, detail="Project root is required.")
    if not entry.ssh_address.strip():
        raise HTTPException(status_code=400, detail="SSH address is required.")
    if not entry.ssh_username.strip():
        raise HTTPException(status_code=400, detail="SSH username is required.")
    if not entry.ssh_key.strip():
        raise HTTPException(status_code=400, detail="SSH key is required.")
    path = _require_db_path()
    try:
        with _open_db(path) as conn:
            conn.execute(
                "INSERT INTO hosts (id, project_root, ssh_address, ssh_username, ssh_key, ssh_port) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    entry.id.strip(),
                    entry.project_root.strip(),
                    entry.ssh_address.strip(),
                    entry.ssh_username.strip(),
                    entry.ssh_key.strip(),
                    entry.ssh_port,
                ),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Host id already exists.") from exc
    _refresh_config_from_db()
    return entry


@app.put("/config/hosts/{host_id}", response_model=HostConfigEntry)
def update_host_config(host_id: str, entry: HostConfigEntry) -> HostConfigEntry:
    if entry.id != host_id:
        raise HTTPException(status_code=400, detail="Host id mismatch.")
    if not entry.project_root.strip():
        raise HTTPException(status_code=400, detail="Project root is required.")
    if not entry.ssh_address.strip():
        raise HTTPException(status_code=400, detail="SSH address is required.")
    if not entry.ssh_username.strip():
        raise HTTPException(status_code=400, detail="SSH username is required.")
    if not entry.ssh_key.strip():
        raise HTTPException(status_code=400, detail="SSH key is required.")
    path = _require_db_path()
    with _open_db(path) as conn:
        cursor = conn.execute(
            "UPDATE hosts SET project_root = ?, ssh_address = ?, ssh_username = ?, ssh_key = ?, ssh_port = ? "
            "WHERE id = ?",
            (
                entry.project_root.strip(),
                entry.ssh_address.strip(),
                entry.ssh_username.strip(),
                entry.ssh_key.strip(),
                entry.ssh_port,
                host_id,
            ),
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Host not found.")
    _refresh_config_from_db()
    return entry


@app.delete("/config/hosts/{host_id}", response_model=SimpleStatusResponse)
def delete_host_config(host_id: str) -> SimpleStatusResponse:
    path = _require_db_path()
    with _open_db(path) as conn:
        cursor = conn.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Host not found.")
        conn.execute("DELETE FROM backup_state WHERE host_id = ?", (host_id,))
        conn.execute("DELETE FROM project_state WHERE host_id = ?", (host_id,))
    _refresh_config_from_db()
    return SimpleStatusResponse(ok=True)


@app.get("/config/backups", response_model=List[BackupConfigEntry])
def list_backup_configs() -> List[BackupConfigEntry]:
    path = _require_db_path()
    with _open_db(path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, address, username, password, base_path, protocol, port, enabled "
            "FROM backups ORDER BY id"
        ).fetchall()
    entries = []
    for row in rows:
        entries.append(
            BackupConfigEntry(
                id=row["id"],
                address=row["address"] or "",
                username=row["username"] or "",
                password=row["password"] or "",
                base_path=row["base_path"] or "",
                protocol=row["protocol"] or "ssh",
                port=int(row["port"] or 22),
                enabled=bool(row["enabled"]),
            )
        )
    return entries


@app.post("/config/backups", response_model=BackupConfigEntry, status_code=201)
def create_backup_config(entry: BackupConfigEntry) -> BackupConfigEntry:
    if not entry.id.strip():
        raise HTTPException(status_code=400, detail="Backup id is required.")
    if not entry.address.strip():
        raise HTTPException(status_code=400, detail="Backup address is required.")
    if not entry.username.strip():
        raise HTTPException(status_code=400, detail="Backup username is required.")
    if not entry.password.strip():
        raise HTTPException(status_code=400, detail="Backup password is required.")
    if not entry.base_path.strip():
        raise HTTPException(status_code=400, detail="Backup base path is required.")
    protocol = entry.protocol.strip().lower()
    if protocol not in ("ssh", "rsync"):
        raise HTTPException(status_code=400, detail="Backup protocol must be ssh or rsync.")
    path = _require_db_path()
    try:
        with _open_db(path) as conn:
            conn.execute(
                "INSERT INTO backups (id, address, username, password, base_path, protocol, port, enabled) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    entry.id.strip(),
                    entry.address.strip(),
                    entry.username.strip(),
                    entry.password.strip(),
                    entry.base_path.strip(),
                    protocol,
                    entry.port,
                    1 if entry.enabled else 0,
                ),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Backup id already exists.") from exc
    _refresh_config_from_db()
    _restart_backup_task()
    return entry


@app.put("/config/backups/{backup_id}", response_model=BackupConfigEntry)
def update_backup_config(backup_id: str, entry: BackupConfigEntry) -> BackupConfigEntry:
    if entry.id != backup_id:
        raise HTTPException(status_code=400, detail="Backup id mismatch.")
    if not entry.address.strip():
        raise HTTPException(status_code=400, detail="Backup address is required.")
    if not entry.username.strip():
        raise HTTPException(status_code=400, detail="Backup username is required.")
    if not entry.password.strip():
        raise HTTPException(status_code=400, detail="Backup password is required.")
    if not entry.base_path.strip():
        raise HTTPException(status_code=400, detail="Backup base path is required.")
    protocol = entry.protocol.strip().lower()
    if protocol not in ("ssh", "rsync"):
        raise HTTPException(status_code=400, detail="Backup protocol must be ssh or rsync.")
    path = _require_db_path()
    with _open_db(path) as conn:
        cursor = conn.execute(
            "UPDATE backups SET address = ?, username = ?, password = ?, base_path = ?, protocol = ?, port = ?, enabled = ? "
            "WHERE id = ?",
            (
                entry.address.strip(),
                entry.username.strip(),
                entry.password.strip(),
                entry.base_path.strip(),
                protocol,
                entry.port,
                1 if entry.enabled else 0,
                backup_id,
            ),
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Backup not found.")
    _refresh_config_from_db()
    _restart_backup_task()
    return entry


@app.delete("/config/backups/{backup_id}", response_model=SimpleStatusResponse)
def delete_backup_config(backup_id: str) -> SimpleStatusResponse:
    path = _require_db_path()
    with _open_db(path) as conn:
        cursor = conn.execute("DELETE FROM backups WHERE id = ?", (backup_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Backup not found.")
    _refresh_config_from_db()
    _restart_backup_task()
    return SimpleStatusResponse(ok=True)


@app.get("/config/users", response_model=List[UserConfigEntry])
def list_user_configs() -> List[UserConfigEntry]:
    path = _require_db_path()
    with _open_db(path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT username, last_login FROM users ORDER BY username"
        ).fetchall()
    return [
        UserConfigEntry(
            username=row["username"],
            last_login=_parse_db_datetime(row["last_login"]),
        )
        for row in rows
    ]


@app.post("/config/users", response_model=UserConfigEntry, status_code=201)
def create_user_config(entry: UserCreateRequest) -> UserConfigEntry:
    username = entry.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required.")
    if not entry.password:
        raise HTTPException(status_code=400, detail="Password is required.")
    password_hash = _hash_password(_secret_seed(), entry.password)
    path = _require_db_path()
    try:
        with _open_db(path) as conn:
            conn.execute(
                "INSERT INTO users (username, password, last_login) VALUES (?, ?, ?)",
                (username, password_hash, None),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="User already exists.") from exc
    return UserConfigEntry(username=username, last_login=None)


@app.put("/config/users/{username}", response_model=UserConfigEntry)
def update_user_config(username: str, entry: UserUpdateRequest) -> UserConfigEntry:
    username = username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required.")
    if entry.password is None or entry.password == "":
        raise HTTPException(status_code=400, detail="Password is required.")
    password_hash = _hash_password(_secret_seed(), entry.password)
    path = _require_db_path()
    with _open_db(path) as conn:
        result = conn.execute(
            "UPDATE users SET password = ? WHERE username = ?",
            (password_hash, username),
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="User not found.")
        row = conn.execute(
            "SELECT last_login FROM users WHERE username = ?", (username,)
        ).fetchone()
    return UserConfigEntry(
        username=username, last_login=_parse_db_datetime(row[0] if row else None)
    )


@app.delete("/config/users/{username}", response_model=SimpleStatusResponse)
def delete_user_config(username: str) -> SimpleStatusResponse:
    username = username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required.")
    if username == "admin":
        raise HTTPException(status_code=403, detail="Admin user cannot be deleted.")
    path = _require_db_path()
    with _open_db(path) as conn:
        result = conn.execute(
            "DELETE FROM users WHERE username = ?", (username,)
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="User not found.")
    return SimpleStatusResponse(ok=True)


@app.get("/config/token-expiry", response_model=IntervalResponse)
def get_token_expiry() -> IntervalResponse:
    return IntervalResponse(seconds=_token_expiry_seconds())


@app.put("/config/token-expiry", response_model=IntervalResponse)
def update_token_expiry(payload: IntervalRequest) -> IntervalResponse:
    seconds = _set_token_expiry(payload.seconds)
    return IntervalResponse(seconds=seconds)


@app.get("/hosts", response_model=List[HostInfo])
def list_hosts() -> List[HostInfo]:
    config = _config()
    return [
        HostInfo(
            host_id=host_id,
            host=host.host,
            user=host.user,
            project_root=host.project_root,
            port=host.port,
        )
        for host_id, host in config.hosts.items()
    ]


@app.get("/hosts/{host_id}/projects", response_model=ProjectListResponse)
def list_projects(host_id: str) -> ProjectListResponse:
    host = _host(host_id)
    try:
        project_paths = compose.list_projects(host)
    except Exception as exc:
        _handle_errors(exc)
    projects = [os.path.basename(path.rstrip("/")) for path in project_paths]
    path_map = {name: path for name, path in zip(projects, project_paths)}
    _ensure_backup_entries(host_id, projects)
    backup_settings = _load_backup_settings(host_id)
    backup_enabled = {}
    backup_last_at = {}
    backup_last_success = {}
    backup_last_message = {}
    backup_cron_override = {}
    for project in projects:
        info = backup_settings.get((host_id, project), {})
        backup_enabled[project] = info.get("enabled", False)
        backup_last_at[project] = info.get("last_backup_at")
        backup_last_success[project] = info.get("last_backup_success")
        backup_last_message[project] = info.get("last_backup_message")
        backup_cron_override[project] = info.get("cron_override")

    return ProjectListResponse(
        host_id=host_id,
        projects=projects,
        project_paths=path_map,
        backup_enabled=backup_enabled,
        backup_last_at=backup_last_at,
        backup_last_success=backup_last_success,
        backup_last_message=backup_last_message,
        backup_cron_override=backup_cron_override,
    )


@app.post("/hosts/{host_id}/sleep", response_model=OperationResponse)
async def sleep_host(host_id: str) -> OperationResponse:
    host = _host(host_id)
    try:
        result = await asyncio.to_thread(_sleep_host_projects, host_id, host)
        await _refresh_status_state([host_id])
    except Exception as exc:
        _handle_errors(exc)
    message = (
        f"Slept {len(result['stopped'])} project(s), "
        f"skipped {len(result['skipped'])} sleeping, "
        f"ignored {len(result['ignored'])} down"
    )
    return OperationResponse(
        host_id=host_id,
        project="*",
        action="sleep",
        output=message,
    )


@app.post("/hosts/{host_id}/wake", response_model=OperationResponse)
async def wake_host(host_id: str) -> OperationResponse:
    host = _host(host_id)
    try:
        result = await asyncio.to_thread(_wake_host_projects, host_id, host)
        await _refresh_status_state([host_id])
    except Exception as exc:
        _handle_errors(exc)
    message = (
        f"Woke {len(result['started'])} project(s), "
        f"cleared {len(result['cleared'])} already running, "
        f"skipped {len(result['skipped'])} not sleeping"
    )
    return OperationResponse(
        host_id=host_id,
        project="*",
        action="wake",
        output=message,
    )


@app.get("/hosts/{host_id}/projects/{project}/status", response_model=ProjectStatusResponse)
def project_status(host_id: str, project: str) -> ProjectStatusResponse:
    host = _host(host_id)
    try:
        overall, containers, issues = compose.project_status(host, project)
    except Exception as exc:
        _handle_errors(exc)
    return ProjectStatusResponse(
        host_id=host_id,
        project=project,
        overall_status=overall,
        containers=[ContainerStatus(**item) for item in containers],
        issues=issues,
    )


@app.get("/hosts/{host_id}/projects/{project}/logs", response_model=LogsResponse)
def project_logs(
    host_id: str,
    project: str,
    tail: int = Query(200, ge=1, le=5000),
    service: Optional[str] = Query(None),
) -> LogsResponse:
    host = _host(host_id)
    try:
        logs = compose.project_logs(host, project, tail=tail, service=service)
    except Exception as exc:
        _handle_errors(exc)
    return LogsResponse(host_id=host_id, project=project, logs=logs)


@app.get("/hosts/{host_id}/projects/{project}/logs/stream")
async def stream_project_logs(
    host_id: str,
    project: str,
    request: Request,
    tail: int = Query(200, ge=1, le=5000),
    service: Optional[str] = Query(None),
) -> StreamingResponse:
    host = _host(host_id)
    command = compose.logs_command(host, project, tail=tail, service=service, follow=True)

    async def event_stream():
        queue: asyncio.Queue[Optional[tuple[str, str]]] = asyncio.Queue()
        stop_event = threading.Event()

        def worker() -> None:
            try:
                for stream, line in stream_ssh_command(
                    host, command, stop_event, timeout=60
                ):
                    asyncio.run_coroutine_threadsafe(
                        queue.put((stream, line)), loop
                    )
            except Exception as exc:
                asyncio.run_coroutine_threadsafe(
                    queue.put(("stderr", f"error: {exc}")), loop
                )
            finally:
                asyncio.run_coroutine_threadsafe(queue.put(None), loop)

        loop = asyncio.get_running_loop()
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()

        try:
            while True:
                if await request.is_disconnected():
                    stop_event.set()
                    break
                item = await queue.get()
                if item is None:
                    break
                stream, line = item
                stream_name = stream if stream in ("stdout", "stderr") else "stdout"
                safe_line = line.replace("\r", "")
                yield f"event: {stream_name}\ndata: {safe_line}\n\n"
        finally:
            stop_event.set()

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get(
    "/hosts/{host_id}/projects/{project}/compose", response_model=ComposeFileResponse
)
def get_compose_file(host_id: str, project: str) -> ComposeFileResponse:
    host = _host(host_id)
    try:
        path, content = compose.read_compose_file(host, project)
    except Exception as exc:
        _handle_errors(exc)
    return ComposeFileResponse(
        host_id=host_id, project=project, path=path, content=content
    )


@app.put(
    "/hosts/{host_id}/projects/{project}/compose", response_model=ComposeFileResponse
)
def update_compose_file(
    host_id: str, project: str, payload: ComposeFileUpdateRequest
) -> ComposeFileResponse:
    host = _host(host_id)
    try:
        path = compose.write_compose_file(host, project, payload.content)
    except Exception as exc:
        _handle_errors(exc)
    return ComposeFileResponse(
        host_id=host_id, project=project, path=path, content=payload.content
    )


@app.post(
    "/hosts/{host_id}/projects/{project}/compose/validate",
    response_model=ComposeValidateResponse,
)
def validate_compose_file(
    host_id: str, project: str, payload: ComposeValidateRequest
) -> ComposeValidateResponse:
    host = _host(host_id)
    try:
        ok, output = compose.validate_compose_content(host, project, payload.content)
    except Exception as exc:
        _handle_errors(exc)
    return ComposeValidateResponse(ok=ok, output=output)


@app.post(
    "/hosts/{host_id}/projects/validate",
    response_model=ComposeValidateResponse,
)
def validate_new_project_compose(
    host_id: str, payload: ComposeValidateRequest
) -> ComposeValidateResponse:
    host = _host(host_id)
    try:
        ok, output = compose.validate_compose_content_temp(host, payload.content)
    except Exception as exc:
        _handle_errors(exc)
    return ComposeValidateResponse(ok=ok, output=output)


@app.post("/auth/token", response_class=PlainTextResponse)
def create_auth_token(payload: AuthTokenRequest) -> str:
    username = payload.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required.")
    stored_password = _get_user_password(username)
    if not stored_password:
        raise HTTPException(status_code=401, detail="Invalid username or auth.")
    provided = _hash_password(_secret_seed(), payload.password)
    if not hmac.compare_digest(stored_password, provided):
        raise HTTPException(status_code=401, detail="Invalid username or auth.")
    token_id = str(uuid.uuid4())
    expiration = _now() + timedelta(seconds=_token_expiry_seconds())
    path = _require_db_path()
    with _open_db(path) as conn:
        conn.execute(
            "INSERT INTO tokens (id, expiration) VALUES (?, ?)",
            (token_id, expiration.isoformat()),
        )
        conn.execute(
            "UPDATE users SET last_login = ? WHERE username = ?",
            (_now().isoformat(), username),
        )
    token_payload = {
        "username": username,
        "id": token_id,
        "expiration": expiration.isoformat(),
    }
    encoded = base64.b64encode(json.dumps(token_payload, separators=(",", ":")).encode()).decode()
    return encoded


@app.post("/compose/convert", response_model=RunToComposeResponse)
def convert_run_to_compose(payload: RunToComposeRequest) -> RunToComposeResponse:
    command = payload.command.strip()
    if not command:
        raise HTTPException(status_code=400, detail="Docker run command is required.")
    try:
        compose_text, service = compose.docker_run_to_compose(command, payload.service)
    except compose.ComposeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _handle_errors(exc)
    return RunToComposeResponse(compose=compose_text, service=service)


@app.post("/hosts/{host_id}/projects", response_model=ProjectCreateResponse)
def create_project(host_id: str, payload: ProjectCreateRequest) -> ProjectCreateResponse:
    host = _host(host_id)
    project = payload.project.strip()
    if not project or project in (".", ".."):
        raise HTTPException(status_code=400, detail="Project name is required.")
    if project != os.path.basename(project):
        raise HTTPException(status_code=400, detail="Project name is invalid.")
    if not payload.content.strip():
        raise HTTPException(status_code=400, detail="Compose content is required.")
    try:
        ok, output = compose.validate_compose_content_temp(host, payload.content)
    except Exception as exc:
        _handle_errors(exc)
    if not ok:
        detail = output or "Compose validation failed."
        raise HTTPException(status_code=400, detail=detail)
    try:
        path = compose.create_project(host, project, payload.content)
    except Exception as exc:
        _handle_errors(exc)
    _record_project_state(host_id, project, path)
    _ensure_backup_entries(host_id, [project])
    if payload.enable_backup:
        _set_backup_enabled(host_id, project, True)
    return ProjectCreateResponse(
        host_id=host_id,
        project=project,
        path=path,
        backup_enabled=bool(payload.enable_backup),
    )


@app.delete("/hosts/{host_id}/projects/{project}", response_model=OperationResponse)
def delete_project(host_id: str, project: str) -> OperationResponse:
    host = _host(host_id)
    project_name = project.strip()
    if not project_name or project_name in (".", ".."):
        raise HTTPException(status_code=400, detail="Project name is required.")
    if project_name != os.path.basename(project_name):
        raise HTTPException(status_code=400, detail="Project name is invalid.")
    try:
        compose.delete_project(host, project_name)
    except Exception as exc:
        _handle_errors(exc)
    db_path = app.state.db_path
    if db_path:
        _ensure_db(db_path)
        with _open_db(db_path) as conn:
            conn.execute(
                "DELETE FROM project_state WHERE host_id = ? AND id = ?",
                (host_id, project_name),
            )
            conn.execute(
                "DELETE FROM backup_state WHERE host_id = ? AND project = ?",
                (host_id, project_name),
            )
            conn.execute(
                "DELETE FROM service_state WHERE host_id = ? AND project_id = ?",
                (host_id, project_name),
            )
    return OperationResponse(
        host_id=host_id,
        project=project_name,
        action="delete",
        output="Project deleted",
    )


@app.get(
    "/hosts/{host_id}/projects/{project}/actions/{action}/stream",
    response_class=StreamingResponse,
)
async def stream_project_action(
    host_id: str, project: str, action: str
) -> StreamingResponse:
    host = _host(host_id)
    action = action.lower()
    if action not in ("start", "stop", "restart", "update"):
        raise HTTPException(status_code=400, detail="Unsupported action")
    stop_event = await _register_action_control(host_id, project, action)

    async def event_generator():
        try:
            yield _sse_event(
                "step", {"step": "running", "message": f"Running {action}"}
            )
            updates_applied, _ = await asyncio.to_thread(
                compose.run_project_action_cancelable, host, project, action, stop_event
            )
            if action in ("start", "restart"):
                await asyncio.to_thread(_set_project_sleeping, host_id, project, False)
            if action == "update":
                await asyncio.to_thread(
                    _mark_project_updates_current, host_id, project, _now()
                )
            payload = {"message": f"{action.capitalize()} complete"}
            if updates_applied is not None:
                payload["updates_applied"] = updates_applied
            yield _sse_event("complete", payload)
        except compose.ComposeCancelled:
            yield _sse_event(
                "complete",
                {"message": f"{action.capitalize()} cancelled", "stopped": True},
            )
        except Exception as exc:
            yield _sse_event("action_error", {"message": str(exc)})
        finally:
            await _clear_action_control(host_id, project, action)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post(
    "/hosts/{host_id}/projects/{project}/actions/{action}/stop",
    response_model=OperationResponse,
)
async def stop_project_action(
    host_id: str, project: str, action: str
) -> OperationResponse:
    _host(host_id)
    action = action.lower()
    if action not in ("start", "stop", "restart", "update"):
        raise HTTPException(status_code=400, detail="Unsupported action")
    stopped = await _request_action_stop(host_id, project, action)
    message = "Stop requested" if stopped else "No active action"
    return OperationResponse(
        host_id=host_id,
        project=project,
        action=f"{action}_stop",
        output=message,
    )


@app.post("/hosts/{host_id}/projects/{project}/start", response_model=OperationResponse)
def start_project(host_id: str, project: str) -> OperationResponse:
    host = _host(host_id)
    try:
        result = compose.start_project(host, project)
        _set_project_sleeping(host_id, project, False)
    except Exception as exc:
        _handle_errors(exc)
    return OperationResponse(
        host_id=host_id, project=project, action="start", output=result.stdout
    )


@app.post("/hosts/{host_id}/projects/{project}/stop", response_model=OperationResponse)
def stop_project(host_id: str, project: str) -> OperationResponse:
    host = _host(host_id)
    try:
        result = compose.stop_project(host, project)
    except Exception as exc:
        _handle_errors(exc)
    return OperationResponse(
        host_id=host_id, project=project, action="stop", output=result.stdout
    )


@app.post("/hosts/{host_id}/projects/{project}/restart", response_model=OperationResponse)
def restart_project(host_id: str, project: str) -> OperationResponse:
    host = _host(host_id)
    try:
        result = compose.restart_project(host, project)
    except Exception as exc:
        _handle_errors(exc)
    return OperationResponse(
        host_id=host_id, project=project, action="restart", output=result.stdout
    )


@app.post("/hosts/{host_id}/projects/{project}/backup", response_model=OperationResponse)
def backup_project(host_id: str, project: str) -> OperationResponse:
    host = _host(host_id)
    backup = _backup_config()
    try:
        dest, output = _backup_with_restart(host_id, host, project, backup)
    except Exception as exc:
        _record_backup_result(host_id, project, False, str(exc))
        _handle_errors(exc)
    message = output.strip() if output else dest
    _record_backup_result(host_id, project, True, message)
    return OperationResponse(
        host_id=host_id, project=project, action="backup", output=message
    )


@app.get(
    "/hosts/{host_id}/projects/{project}/backup/stream",
    response_class=StreamingResponse,
)
async def backup_project_stream(host_id: str, project: str) -> StreamingResponse:
    host = _host(host_id)
    backup = _backup_config()

    async def event_generator():
        running = False
        project_stopped = False
        started_again = False
        stop_event = await _register_backup_control(host_id, project)
        try:
            yield _sse_event("step", {"step": "checking", "message": "Checking status"})
            overall, containers, _ = await asyncio.to_thread(
                compose.project_status, host, project
            )
            running = _is_project_running(overall, containers)
            if running:
                yield _sse_event("step", {"step": "stopping", "message": "Stopping project"})
                await asyncio.to_thread(compose.stop_project, host, project)
                project_stopped = True
            if stop_event.is_set():
                yield _sse_event("step", {"step": "stopped", "message": "Backup stopped"})
                await asyncio.to_thread(
                    _record_backup_result,
                    host_id,
                    project,
                    False,
                    "Backup stopped",
                )
                yield _sse_event(
                    "complete",
                    {"message": "Backup stopped", "stopped": True},
                )
                return
            yield _sse_event("step", {"step": "backup", "message": "Running backup"})
            dest, command = await asyncio.to_thread(
                compose.build_backup_command, host_id, host, project, backup
            )
            queue: asyncio.Queue[Optional[tuple[str, str]]] = asyncio.Queue()
            loop = asyncio.get_running_loop()

            def worker() -> None:
                try:
                    for stream_name, line in stream_ssh_command(
                        host, command, stop_event, timeout=600
                    ):
                        asyncio.run_coroutine_threadsafe(
                            queue.put((stream_name, line)), loop
                        )
                except Exception as exc:
                    asyncio.run_coroutine_threadsafe(
                        queue.put(("stderr", f"error: {exc}")), loop
                    )
                finally:
                    asyncio.run_coroutine_threadsafe(queue.put(None), loop)

            thread = threading.Thread(target=worker, daemon=True)
            thread.start()

            while True:
                item = await queue.get()
                if item is None:
                    break
                stream_name, line = item
                if line.strip():
                    yield _sse_event("output", {"stream": stream_name, "message": line})
            if stop_event.is_set():
                yield _sse_event("step", {"step": "stopped", "message": "Backup stopped"})
                await asyncio.to_thread(
                    _record_backup_result,
                    host_id,
                    project,
                    False,
                    "Backup stopped",
                )
                yield _sse_event(
                    "complete",
                    {"message": "Backup stopped", "stopped": True},
                )
                return
            if running:
                yield _sse_event("step", {"step": "starting", "message": "Starting project"})
                await asyncio.to_thread(compose.start_project, host, project)
                started_again = True
            message = dest or "Backup complete"
            await asyncio.to_thread(
                _record_backup_result, host_id, project, True, message
            )
            yield _sse_event(
                "complete", {"message": "Backup complete", "destination": dest}
            )
        except Exception as exc:
            await asyncio.to_thread(
                _record_backup_result, host_id, project, False, str(exc)
            )
            if running:
                try:
                    yield _sse_event(
                        "step", {"step": "starting", "message": "Starting project"}
                    )
                    await asyncio.to_thread(compose.start_project, host, project)
                    started_again = True
                except Exception as start_exc:
                    yield _sse_event(
                        "step",
                        {"step": "start_failed", "message": f"Start failed: {start_exc}"},
                    )
            yield _sse_event("backup_error", {"message": str(exc)})
        finally:
            if running and project_stopped and not started_again:
                with contextlib.suppress(Exception):
                    await asyncio.to_thread(compose.start_project, host, project)
            await _clear_backup_control(host_id, project)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post(
    "/hosts/{host_id}/projects/{project}/backup/stop",
    response_model=OperationResponse,
)
async def stop_backup(host_id: str, project: str) -> OperationResponse:
    _host(host_id)
    stopped = await _request_backup_stop(host_id, project)
    message = "Stop requested" if stopped else "No active backup"
    return OperationResponse(
        host_id=host_id, project=project, action="backup_stop", output=message
    )


@app.get(
    "/hosts/{host_id}/projects/{project}/backup/settings",
    response_model=BackupSettingsResponse,
)
def get_backup_settings(host_id: str, project: str) -> BackupSettingsResponse:
    _host(host_id)
    if not app.state.db_path:
        raise HTTPException(status_code=400, detail="DB_PATH not configured.")
    _ensure_backup_entries(host_id, [project])
    info = _load_backup_settings(host_id).get((host_id, project), {})
    cron_override = info.get("cron_override")
    global_cron = _load_backup_cron()
    effective_cron = cron_override or global_cron
    next_run = None
    if effective_cron:
        next_run = _next_cron_run(effective_cron, info.get("last_backup_at") or _now())
    return BackupSettingsResponse(
        host_id=host_id,
        project=project,
        enabled=info.get("enabled", False),
        last_backup_at=info.get("last_backup_at"),
        last_backup_success=info.get("last_backup_success"),
        last_backup_message=info.get("last_backup_message"),
        cron_override=cron_override,
        effective_cron=effective_cron,
        next_run=next_run,
    )


@app.put(
    "/hosts/{host_id}/projects/{project}/backup/settings",
    response_model=BackupSettingsResponse,
)
def update_backup_settings(
    host_id: str, project: str, payload: BackupSettingsRequest
) -> BackupSettingsResponse:
    _host(host_id)
    if not app.state.db_path:
        raise HTTPException(status_code=400, detail="DB_PATH not configured.")
    info = {}
    if "enabled" in payload.model_fields_set and payload.enabled is not None:
        info = _set_backup_enabled(host_id, project, payload.enabled)
    if "cron_override" in payload.model_fields_set:
        cron_expr = (payload.cron_override or "").strip() or None
        if cron_expr and not _next_cron_run(cron_expr, _now()):
            raise HTTPException(status_code=400, detail="Invalid cron expression.")
        info = _set_backup_cron_override(host_id, project, cron_expr)
        app.state.backup_schedule_map.pop(_backup_key(host_id, project), None)
    app.state.backup_schedule_event.set()
    if not info:
        info = _load_backup_settings(host_id).get((host_id, project), {})
    cron_override = info.get("cron_override")
    global_cron = _load_backup_cron()
    effective_cron = cron_override or global_cron
    next_run = None
    if effective_cron:
        next_run = _next_cron_run(effective_cron, info.get("last_backup_at") or _now())
    return BackupSettingsResponse(
        host_id=host_id,
        project=project,
        enabled=info.get("enabled", payload.enabled or False),
        last_backup_at=info.get("last_backup_at"),
        last_backup_success=info.get("last_backup_success"),
        last_backup_message=info.get("last_backup_message"),
        cron_override=cron_override,
        effective_cron=effective_cron,
        next_run=next_run,
    )


@app.post(
    "/hosts/{host_id}/projects/{project}/services/{service}/start",
    response_model=OperationResponse,
)
def start_service(host_id: str, project: str, service: str) -> OperationResponse:
    host = _host(host_id)
    try:
        result = compose.start_service(host, project, service)
    except Exception as exc:
        _handle_errors(exc)
    return OperationResponse(
        host_id=host_id,
        project=project,
        action=f"service:{service}:start",
        output=result.stdout,
    )


@app.get(
    "/hosts/{host_id}/projects/{project}/services/{service}/actions/{action}/stream",
    response_class=StreamingResponse,
)
async def stream_service_action(
    host_id: str, project: str, service: str, action: str
) -> StreamingResponse:
    host = _host(host_id)
    action = action.lower()
    if action not in ("start", "stop", "restart"):
        raise HTTPException(status_code=400, detail="Unsupported action")
    stop_event = await _register_service_action_control(
        host_id, project, service, action
    )

    async def event_generator():
        try:
            yield _sse_event(
                "step", {"step": "running", "message": f"Running {action}"}
            )
            await asyncio.to_thread(
                compose.run_service_action_cancelable,
                host,
                project,
                service,
                action,
                stop_event,
            )
            payload = {"message": f"{action.capitalize()} complete"}
            yield _sse_event("complete", payload)
        except compose.ComposeCancelled:
            yield _sse_event(
                "complete",
                {"message": f"{action.capitalize()} cancelled", "stopped": True},
            )
        except Exception as exc:
            yield _sse_event("action_error", {"message": str(exc)})
        finally:
            await _clear_service_action_control(host_id, project, service, action)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post(
    "/hosts/{host_id}/projects/{project}/services/{service}/actions/{action}/stop",
    response_model=OperationResponse,
)
async def stop_service_action(
    host_id: str, project: str, service: str, action: str
) -> OperationResponse:
    _host(host_id)
    action = action.lower()
    if action not in ("start", "stop", "restart"):
        raise HTTPException(status_code=400, detail="Unsupported action")
    stopped = await _request_service_action_stop(host_id, project, service, action)
    message = "Stop requested" if stopped else "No active action"
    return OperationResponse(
        host_id=host_id,
        project=project,
        action=f"service:{service}:{action}_stop",
        output=message,
    )


@app.post(
    "/hosts/{host_id}/projects/{project}/services/{service}/stop",
    response_model=OperationResponse,
)
def stop_service(host_id: str, project: str, service: str) -> OperationResponse:
    host = _host(host_id)
    try:
        result = compose.stop_service(host, project, service)
    except Exception as exc:
        _handle_errors(exc)
    return OperationResponse(
        host_id=host_id,
        project=project,
        action=f"service:{service}:stop",
        output=result.stdout,
    )


@app.post(
    "/hosts/{host_id}/projects/{project}/services/{service}/restart",
    response_model=OperationResponse,
)
def restart_service(host_id: str, project: str, service: str) -> OperationResponse:
    host = _host(host_id)
    try:
        result = compose.restart_service(host, project, service)
    except Exception as exc:
        _handle_errors(exc)
    return OperationResponse(
        host_id=host_id,
        project=project,
        action=f"service:{service}:restart",
        output=result.stdout,
    )


@app.get("/hosts/{host_id}/projects/{project}/updates", response_model=UpdateCheckResponse)
def check_updates(host_id: str, project: str) -> UpdateCheckResponse:
    host = _host(host_id)
    try:
        supported, updates_available, details, per_service = compose.check_updates(
            host, project
        )
    except Exception as exc:
        _handle_errors(exc)
    return UpdateCheckResponse(
        host_id=host_id,
        project=project,
        supported=supported,
        updates_available=updates_available,
        details=details,
        per_service=per_service,
    )


@app.post("/hosts/{host_id}/projects/{project}/update", response_model=UpdateApplyResponse)
def apply_updates(host_id: str, project: str) -> UpdateApplyResponse:
    host = _host(host_id)
    try:
        updates_applied, output = compose.apply_updates(host, project)
        _mark_project_updates_current(host_id, project, _now())
    except Exception as exc:
        _handle_errors(exc)
    return UpdateApplyResponse(
        host_id=host_id,
        project=project,
        updates_applied=updates_applied,
        output=output,
    )


@app.get("/state", response_model=StateResponse)
async def get_state() -> StateResponse:
    async with app.state.state_lock:
        data = await asyncio.to_thread(_load_state_from_db)
    hosts = [HostStateResponse(**item) for item in data["hosts"]]
    return StateResponse(
        refreshed_at=data["refreshed_at"],
        updates_enabled=compose.UPDATE_CHECKS_ENABLED,
        hosts=hosts,
    )


@app.get("/hosts/{host_id}/state", response_model=HostStateResponse)
async def get_host_state(host_id: str) -> HostStateResponse:
    _host(host_id)
    async with app.state.state_lock:
        data = await asyncio.to_thread(_load_state_from_db, host_id)
    if data["hosts"]:
        return HostStateResponse(**data["hosts"][0])
    return HostStateResponse(host_id=host_id)


@app.post(
    "/hosts/{host_id}/projects/{project}/state/refresh",
    response_model=StateRefreshResponse,
)
async def refresh_project_state_endpoint(
    host_id: str, project: str
) -> StateRefreshResponse:
    _host(host_id)
    refreshed_at = await _refresh_project_state(host_id, project)
    return StateRefreshResponse(refreshed_at=refreshed_at)


@app.get("/state/interval", response_model=IntervalResponse)
async def get_state_interval() -> IntervalResponse:
    return IntervalResponse(seconds=app.state.state_interval_seconds)


@app.put("/state/interval", response_model=IntervalResponse)
async def update_state_interval(
    payload: IntervalRequest,
) -> IntervalResponse:
    if payload.seconds < 0:
        raise HTTPException(status_code=400, detail="seconds must be >= 0")
    await _set_state_interval(payload.seconds)
    return IntervalResponse(seconds=app.state.state_interval_seconds)


@app.get("/update/interval", response_model=IntervalResponse)
async def get_update_interval() -> IntervalResponse:
    return IntervalResponse(seconds=app.state.update_interval_seconds)


@app.put("/update/interval", response_model=IntervalResponse)
async def update_update_interval(
    payload: IntervalRequest,
) -> IntervalResponse:
    if payload.seconds < 0:
        raise HTTPException(status_code=400, detail="seconds must be >= 0")
    await _set_update_interval(payload.seconds)
    return IntervalResponse(seconds=app.state.update_interval_seconds)


@app.get("/backup/schedule", response_model=BackupScheduleResponse)
async def get_backup_schedule() -> BackupScheduleResponse:
    if not app.state.db_path:
        raise HTTPException(status_code=400, detail="DB_PATH not configured.")
    cron_expr, enabled = await asyncio.to_thread(_load_backup_cron_state)
    next_run = None
    if enabled and cron_expr:
        next_run = await asyncio.to_thread(_next_cron_run, cron_expr, _now())
    return BackupScheduleResponse(
        cron=cron_expr, enabled=enabled, next_run=next_run
    )


@app.put("/backup/schedule", response_model=BackupScheduleResponse)
async def update_backup_schedule(
    payload: BackupScheduleRequest,
) -> BackupScheduleResponse:
    if not app.state.db_path:
        raise HTTPException(status_code=400, detail="DB_PATH not configured.")
    cron_expr = (payload.cron or "").strip() or None
    enabled = payload.enabled if payload.enabled is not None else bool(cron_expr)
    if enabled and not cron_expr:
        raise HTTPException(status_code=400, detail="Cron expression required.")
    if cron_expr:
        next_run = _next_cron_run(cron_expr, _now())
        if not next_run:
            raise HTTPException(status_code=400, detail="Invalid cron expression.")
    await asyncio.to_thread(_persist_backup_cron, cron_expr, enabled)
    await _stop_backup_task()
    app.state.backup_schedule_map = {}
    app.state.backup_task = _start_backup_task()
    next_run = _next_cron_run(cron_expr, _now()) if enabled and cron_expr else None
    return BackupScheduleResponse(
        cron=cron_expr, enabled=enabled, next_run=next_run
    )


@app.post("/hosts/{host_id}/state/refresh", response_model=StateRefreshResponse)
async def refresh_host_state_endpoint(host_id: str) -> StateRefreshResponse:
    _host(host_id)
    refreshed_at = await _refresh_state([host_id])
    return StateRefreshResponse(refreshed_at=refreshed_at)
