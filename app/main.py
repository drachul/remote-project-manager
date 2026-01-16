import asyncio
import base64
import contextlib
import hashlib
import hmac
import json
import logging
import os
import resource
import secrets
import shlex
import sqlite3
import string
import stat
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional

import grp
import pwd

from croniter import croniter, CroniterBadCronError, CroniterBadDateError

from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
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
    BackupTargetEntry,
    BackupProjectsResponse,
    BackupRestoreRequest,
    SimpleStatusResponse,
    ComposeFileResponse,
    ComposeFileUpdateRequest,
    ProjectCreateRequest,
    ProjectCreateResponse,
    ComposeValidateRequest,
    ComposeValidateResponse,
    ComposeCommandRequest,
    ComposeCommandResponse,
    ContainerStatus,
    HostInfo,
    HostStateResponse,
    LogsResponse,
    OperationResponse,
    ProjectListResponse,
    ProjectStatusResponse,
    ProjectStatEntry,
    ProjectStatsResponse,
    ProjectPortEntry,
    ProjectPortsResponse,
    UpdateApplyResponse,
    UpdateCheckResponse,
    AuthTokenRequest,
    PasswordChangeRequest,
    UserConfigEntry,
    UserCreateRequest,
    UserUpdateRequest,
    RunToComposeRequest,
    RunToComposeResponse,
    EventStatusEntry,
    EventStatusResponse,
    BackupScheduleSummaryEntry,
    BackupScheduleSummaryResponse,
)
from .ssh import SSHError, open_ssh_shell, stream_ssh_command

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
DB_OPEN_ATTEMPTS = int(os.getenv("DB_OPEN_ATTEMPTS", "5"))
DB_OPEN_DELAY_SECONDS = float(os.getenv("DB_OPEN_DELAY_SECONDS", "0.2"))
FD_LIMIT_TARGET = int(os.getenv("APP_FD_LIMIT", "4096"))

ROLE_ADMIN = "admin"
ROLE_POWER = "power"
ROLE_NORMAL = "normal"
VALID_ROLES = {ROLE_ADMIN, ROLE_POWER, ROLE_NORMAL}
FD_TRACK_INTERVAL_SECONDS = int(os.getenv("APP_FD_TRACK_INTERVAL", "300"))
FD_TRACK_TOP = int(os.getenv("APP_FD_TRACK_TOP", "0"))


def _ensure_fd_limit() -> None:
    if FD_LIMIT_TARGET <= 0:
        return
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (ValueError, OSError) as exc:
        logger.debug("FD limit check failed: %s", exc)
        return
    target = min(hard, max(soft, FD_LIMIT_TARGET))
    if target <= soft:
        return
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
        logger.debug("FD limit raised soft=%s hard=%s", target, hard)
    except (ValueError, OSError) as exc:
        logger.debug("FD limit update failed soft=%s hard=%s error=%s", target, hard, exc)


@app.get("/")
def ui_index() -> HTMLResponse:
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(html)


@app.on_event("startup")
async def load_settings() -> None:
    app.state.loop = asyncio.get_running_loop()
    _ensure_fd_limit()
    app.state.config = load_config()
    _configure_logging(app.state.config.log_level)
    app.state.db_path = _db_path()
    if not app.state.db_path:
        raise ConfigError("DB_PATH is not configured.")
    _log_db_path_diagnostics(app.state.db_path)
    _ensure_db(app.state.db_path)
    app.state.config = _load_config_from_db(app.state.config)
    logger.info("Starting Remote Project Manager")
    app.state.state_lock = asyncio.Lock()
    app.state.backup_lock = asyncio.Lock()
    app.state.backup_controls = {}
    app.state.action_lock = asyncio.Lock()
    app.state.action_controls = {}
    app.state.backup_schedule_map = {}
    app.state.backup_schedule_event = asyncio.Event()
    app.state.secret_seed = _load_secret_seed()
    app.state.token_expiry_seconds = _load_token_expiry()
    app.state.state_interval_seconds = _load_interval_setting(
        "state_interval_seconds", _state_interval_seconds()
    )
    app.state.update_interval_seconds = _load_interval_setting(
        "update_interval_seconds", _update_interval_seconds()
    )
    app.state.event_status = _init_event_status()
    now = _now()
    if app.state.state_interval_seconds > 0:
        _set_event_next_run("status_refresh", now + timedelta(seconds=app.state.state_interval_seconds))
    if app.state.update_interval_seconds > 0:
        _set_event_next_run("update_refresh", now + timedelta(seconds=app.state.update_interval_seconds))
    if app.state.db_path:
        _set_event_next_run("token_cleanup", now + timedelta(seconds=TOKEN_CLEANUP_INTERVAL_SECONDS))
    if FD_TRACK_INTERVAL_SECONDS > 0:
        _set_event_next_run("fd_track", now + timedelta(seconds=FD_TRACK_INTERVAL_SECONDS))
    app.state.state_task = _start_state_task()
    app.state.update_task = _start_update_task()
    app.state.backup_task = _start_backup_task()
    app.state.token_cleanup_task = _start_token_cleanup_task()
    app.state.fd_task = _start_fd_track_task()
    logger.info("Startup complete")


@app.on_event("shutdown")
async def shutdown_tasks() -> None:
    logger.info("Shutting down")
    for task_name in ("state_task", "update_task", "backup_task", "token_cleanup_task", "fd_task"):
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
        _authorize_request(request)
    except HTTPException as exc:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    return await call_next(request)


def _now() -> datetime:
    return datetime.now(timezone.utc)

EVENT_DEFINITIONS = {
    "status_refresh": {
        "label": "Project status refresh",
        "description": "Refreshes one project's status based on the oldest refresh timestamp.",
    },
    "update_refresh": {
        "label": "Image update check",
        "description": "Checks for a service image update based on the oldest update check.",
    },
    "backup_schedule": {
        "label": "Scheduled backups",
        "description": "Runs scheduled backups for enabled projects using cron settings.",
    },
    "token_cleanup": {
        "label": "Token cleanup",
        "description": "Removes expired authentication tokens from the database.",
    },
    "fd_track": {
        "label": "FD usage tracker",
        "description": "Logs periodic file descriptor usage to help spot leaks.",
    },
}


def _init_event_status() -> Dict[str, dict]:
    return {
        key: {"last_run": None, "last_success": None, "last_result": None, "next_run": None}
        for key in EVENT_DEFINITIONS
    }


def _record_event_result(
    key: str,
    success: Optional[bool],
    message: Optional[str],
    run_at: Optional[datetime] = None,
) -> None:
    status = getattr(app.state, "event_status", None)
    if status is None:
        return
    entry = status.setdefault(key, {})
    entry["last_run"] = run_at or _now()
    entry["last_success"] = success
    if message is not None:
        entry["last_result"] = message


def _set_event_next_run(key: str, next_run: Optional[datetime]) -> None:
    status = getattr(app.state, "event_status", None)
    if status is None:
        return
    entry = status.setdefault(key, {})
    entry["next_run"] = next_run


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


def _normalize_role(value: Optional[str]) -> str:
    role = (value or "").strip().lower()
    if role in VALID_ROLES:
        return role
    return ROLE_NORMAL


def _get_request_role(request: Request) -> str:
    return _normalize_role(getattr(request.state, "user_role", ROLE_NORMAL))


def _required_roles_for_request(path: str, method: str) -> set[str]:
    method = method.upper()
    roles_all = {ROLE_ADMIN, ROLE_POWER, ROLE_NORMAL}
    roles_power = {ROLE_ADMIN, ROLE_POWER}
    roles_admin = {ROLE_ADMIN}

    if path.startswith("/config/"):
        return roles_admin
    if path in ("/state/interval", "/update/interval", "/config/token-expiry"):
        return roles_admin
    if path.startswith("/backup/schedule"):
        return roles_admin
    if path.startswith("/backup/targets") or path == "/backup/restore":
        return roles_admin
    if path == "/events/status":
        return roles_admin
    if path == "/compose/convert":
        return roles_admin
    if path.startswith("/hosts/"):
        parts = [part for part in path.strip("/").split("/") if part]
        if len(parts) >= 3 and parts[2] in ("sleep", "wake"):
            return roles_power
        if len(parts) >= 3 and parts[2] == "state":
            if len(parts) >= 4 and parts[3] == "refresh":
                return roles_power
            return roles_all
        if len(parts) >= 3 and parts[2] == "projects":
            if len(parts) == 3:
                if method == "POST":
                    return roles_admin
                return roles_all
            if len(parts) == 4 and parts[3] == "validate":
                return roles_admin
            if len(parts) >= 4:
                if len(parts) == 4:
                    if method == "DELETE":
                        return roles_admin
                    return roles_all
                action = parts[4]
                if action == "compose":
                    if len(parts) >= 6 and parts[5] == "command":
                        return roles_power
                    return roles_admin
                if action == "updates":
                    return roles_power
                if action == "update":
                    return roles_power
                if action in ("start", "stop", "restart", "hard_restart"):
                    return roles_power
                if action == "backup":
                    return roles_admin
                if action in ("actions", "services"):
                    return roles_power
                if action == "logs":
                    return roles_all
                if action in ("status", "stats", "ports"):
                    return roles_all
        return roles_all
    return roles_all


def _authorize_request(request: Request) -> None:
    required = _required_roles_for_request(request.url.path, request.method)
    role = _get_request_role(request)
    if role in required:
        return
    if required == {ROLE_ADMIN}:
        detail = "Admin access required."
    elif required == {ROLE_ADMIN, ROLE_POWER}:
        detail = "Action requires admin or power user."
    else:
        detail = "Insufficient permissions."
    raise HTTPException(status_code=403, detail=detail)


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


def _extract_bearer_token(header: Optional[str]) -> str:
    if not header:
        raise HTTPException(status_code=401, detail="Authorization header missing.")
    if not header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Authorization must be Bearer token.")
    token = header.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Authorization token missing.")
    return token


def _verify_token_value(token: str) -> tuple[str, str]:
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
            "SELECT password, role FROM users WHERE username = ?", (username,)
        ).fetchone()
        if not user_row:
            raise HTTPException(status_code=401, detail="User not found.")
        role = _normalize_role(user_row[1])
        token_row = conn.execute(
            "SELECT 1 FROM tokens WHERE id = ? AND expiration = ?",
            (token_id, expiration_value),
        ).fetchone()
        if not token_row:
            raise HTTPException(status_code=401, detail="Token not recognized.")
    return username, role


def _verify_request_token(request: Request) -> None:
    token = _extract_bearer_token(request.headers.get("authorization"))
    username, role = _verify_token_value(token)
    request.state.username = username
    request.state.user_role = role


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


def _connect_db_uri(path: str) -> sqlite3.Connection:
    uri_path = Path(path).resolve().as_uri()
    return sqlite3.connect(f"{uri_path}?mode=rwc", uri=True, timeout=5)


def _connect_db(path: str) -> sqlite3.Connection:
    attempts = max(1, DB_OPEN_ATTEMPTS)
    delay = max(0.0, DB_OPEN_DELAY_SECONDS)
    last_exc: Optional[sqlite3.OperationalError] = None
    for attempt in range(1, attempts + 1):
        try:
            return sqlite3.connect(path, timeout=5)
        except sqlite3.OperationalError as exc:
            last_exc = exc
            message = str(exc).lower()
            if "unable to open database file" not in message:
                _log_db_path_diagnostics(path)
                raise
            try:
                return _connect_db_uri(path)
            except sqlite3.OperationalError as uri_exc:
                last_exc = uri_exc
                logger.debug(
                    "DB open failed path=%s attempt=%s/%s error=%s",
                    path,
                    attempt,
                    attempts,
                    exc,
                )
                logger.debug(
                    "DB open failed uri path=%s attempt=%s/%s error=%s",
                    path,
                    attempt,
                    attempts,
                    uri_exc,
                )
            if attempt < attempts and delay > 0:
                time.sleep(delay * attempt)
    if last_exc:
        _log_db_path_diagnostics(path)
        logger.debug("DB open failed after %s attempts: %s", attempts, last_exc)
        raise last_exc
    return sqlite3.connect(path, timeout=5)


def _user_name(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _group_name(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def _access_flags(path: str) -> str:
    return "".join(
        [
            "r" if os.access(path, os.R_OK) else "-",
            "w" if os.access(path, os.W_OK) else "-",
            "x" if os.access(path, os.X_OK) else "-",
        ]
    )


def _log_path_info(label: str, path: str) -> None:
    exists = os.path.exists(path) or os.path.islink(path)
    is_file = os.path.isfile(path)
    is_dir = os.path.isdir(path)
    is_link = os.path.islink(path)
    mode = "n/a"
    owner = "n/a"
    group = "n/a"
    if exists or is_link:
        try:
            info = os.lstat(path)
            mode = oct(stat.S_IMODE(info.st_mode))
            owner = _user_name(info.st_uid)
            group = _group_name(info.st_gid)
        except OSError:
            pass
    logger.debug(
        "DB path info label=%s path=%s exists=%s is_file=%s is_dir=%s is_link=%s mode=%s owner=%s group=%s access=%s",
        label,
        path,
        exists,
        is_file,
        is_dir,
        is_link,
        mode,
        owner,
        group,
        _access_flags(path),
    )


def _log_fd_diagnostics() -> None:
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        logger.debug("DB fd limits soft=%s hard=%s", soft, hard)
    except (ValueError, OSError):
        logger.debug("DB fd limits unavailable")
    try:
        fd_count = len(os.listdir("/proc/self/fd"))
        logger.debug("DB fd open_count=%s", fd_count)
    except OSError:
        logger.debug("DB fd open_count unavailable")


def _probe_db_path_access(path: str) -> None:
    parent = os.path.dirname(path) or "."
    probe_path = os.path.join(parent, f".rpm-db-probe-{os.getpid()}")
    try:
        fd = os.open(probe_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        os.unlink(probe_path)
        logger.debug("DB path probe write ok path=%s", parent)
    except OSError as exc:
        logger.debug("DB path probe write failed path=%s error=%s errno=%s", parent, exc, exc.errno)
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        os.close(fd)
        logger.debug("DB path probe open ok path=%s", path)
    except OSError as exc:
        logger.debug("DB path probe open failed path=%s error=%s errno=%s", path, exc, exc.errno)


def _log_db_path_diagnostics(path: str) -> None:
    logger.debug(
        "DB path diagnostics user=%s uid=%s group=%s gid=%s",
        _user_name(os.geteuid()),
        os.geteuid(),
        _group_name(os.getegid()),
        os.getegid(),
    )
    _log_path_info("db_path", path)
    parent = os.path.dirname(path) or "."
    _log_path_info("db_parent", parent)
    try:
        stats = os.statvfs(parent)
        free_bytes = stats.f_bavail * stats.f_frsize
        total_bytes = stats.f_blocks * stats.f_frsize
        logger.debug(
            "DB path filesystem free_bytes=%s total_bytes=%s",
            free_bytes,
            total_bytes,
        )
    except OSError:
        logger.debug("DB path filesystem stats unavailable for %s", parent)
    _probe_db_path_access(path)
    _log_fd_diagnostics()


def _collect_fd_stats() -> Optional[dict]:
    fd_dir = "/proc/self/fd"
    try:
        with os.scandir(fd_dir) as it:
            entries = list(it)
    except OSError as exc:
        logger.debug("FD scan failed path=%s error=%s", fd_dir, exc)
        return None
    counts = {
        "total": 0,
        "socket": 0,
        "pipe": 0,
        "anon": 0,
        "file": 0,
        "other": 0,
    }
    targets = {} if FD_TRACK_TOP > 0 else None
    for entry in entries:
        counts["total"] += 1
        try:
            target = os.readlink(entry.path)
        except OSError:
            counts["other"] += 1
            continue
        if target.startswith("socket:"):
            counts["socket"] += 1
        elif target.startswith("pipe:"):
            counts["pipe"] += 1
        elif target.startswith("anon_inode:"):
            counts["anon"] += 1
        elif target.startswith("/"):
            counts["file"] += 1
        else:
            counts["other"] += 1
        if targets is not None:
            targets[target] = targets.get(target, 0) + 1
    if targets is not None:
        counts["targets"] = targets
    return counts


def _log_fd_usage() -> Optional[str]:
    stats = _collect_fd_stats()
    if not stats:
        return None
    summary = (
        f"total={stats.get('total')} sockets={stats.get('socket')} "
        f"pipes={stats.get('pipe')} anon={stats.get('anon')} "
        f"files={stats.get('file')} other={stats.get('other')}"
    )
    logger.debug("FD usage %s", summary)
    targets = stats.get("targets")
    if FD_TRACK_TOP > 0 and targets:
        items = sorted(targets.items(), key=lambda item: (-item[1], item[0]))[:FD_TRACK_TOP]
        top_summary = ", ".join(
            f"{count}x {target[:120]}" for target, count in items
        )
        logger.debug("FD top targets: %s", top_summary)
        summary = f"{summary}; top={top_summary}"
    return summary


def _ensure_db(path: str, *, log_exception: bool = True) -> None:
    if os.path.isdir(path):
        raise ConfigError(f"db_path points to a directory: {path}")
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    try:
        with _open_db(path) as conn:
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
                "last_login DATETIME, "
                "role TEXT NOT NULL DEFAULT 'normal'"
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
                "last_backup_failure TEXT, "
                "PRIMARY KEY (host_id, project), "
                "FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE"
                ")"
            )
            _ensure_column(conn, "service_state", "update_checked_at", "DATETIME")
            _ensure_column(conn, "backup_state", "last_backup_message", "TEXT")
            _ensure_column(conn, "backup_state", "last_backup_failure", "TEXT")
            _ensure_column(conn, "backup_state", "cron_override", "TEXT")
            _ensure_column(conn, "project_state", "sleeping", "BOOLEAN DEFAULT 0")
            _ensure_column(conn, "backups", "enabled", "BOOLEAN DEFAULT 1")
            _ensure_column(conn, "users", "role", "TEXT NOT NULL DEFAULT 'normal'")
            conn.execute(
                "UPDATE users SET role = ? WHERE role IS NULL OR role = ''",
                (ROLE_NORMAL,),
            )
            conn.execute(
                "UPDATE users SET role = ? WHERE username = ?",
                (ROLE_ADMIN, "admin"),
            )
            admin_exists = conn.execute(
                "SELECT 1 FROM users WHERE username = ?", ("admin",)
            ).fetchone()
            if not admin_exists:
                admin_hash = _hash_password(_secret_seed(), "changemenow")
                conn.execute(
                    "INSERT INTO users (username, password, last_login, role) VALUES (?, ?, ?, ?)",
                    ("admin", admin_hash, None, ROLE_ADMIN),
                )
    except sqlite3.OperationalError as exc:
        _log_db_path_diagnostics(path)
        if log_exception:
            logger.exception("DB init failed for path=%s", path)
        else:
            logger.debug("DB init failed for path=%s", path)
        raise ConfigError(f"Unable to open db_path {path}: {exc}") from exc


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    existing = {row[1] for row in rows}
    if column in existing:
        return
    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _read_interval_setting(path: str, key: str) -> Optional[int]:
    with _open_db(path) as conn:
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
    with _open_db(path) as conn:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, str(value)),
        )


def _read_setting(path: str, key: str) -> Optional[str]:
    with _open_db(path) as conn:
        row = conn.execute(
            "SELECT value FROM settings WHERE key = ?", (key,)
        ).fetchone()
    if not row:
        return None
    return row[0]


def _write_setting(path: str, key: str, value: Optional[str]) -> None:
    with _open_db(path) as conn:
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
                "last_backup_success, last_backup_message, last_backup_failure "
                "FROM backup_state WHERE host_id = ?",
                (host_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT host_id, project, enabled, cron_override, last_backup_at, "
                "last_backup_success, last_backup_message, last_backup_failure "
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
            "last_backup_failure": row["last_backup_failure"],
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
            "SELECT enabled, cron_override, last_backup_at, last_backup_success, last_backup_message, last_backup_failure "
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
        "last_backup_failure": row[5] if row else None,
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
            "SELECT enabled, cron_override, last_backup_at, last_backup_success, last_backup_message, last_backup_failure "
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
        "last_backup_failure": row[5] if row else None,
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
            "(host_id, project, enabled, last_backup_at, last_backup_success, last_backup_message, last_backup_failure) "
            "VALUES (?, ?, COALESCE((SELECT enabled FROM backup_state WHERE host_id = ? AND project = ?), 0), ?, ?, ?, ?) "
            "ON CONFLICT(host_id, project) DO UPDATE SET "
            "last_backup_at = excluded.last_backup_at, "
            "last_backup_success = excluded.last_backup_success, "
            "last_backup_message = excluded.last_backup_message, "
            "last_backup_failure = CASE "
            "WHEN excluded.last_backup_success = 0 THEN excluded.last_backup_failure "
            "ELSE backup_state.last_backup_failure END",
            (
                host_id,
                project,
                host_id,
                project,
                _now().isoformat(),
                1 if success else 0,
                message,
                message if not success else None,
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


@contextlib.contextmanager
def _open_db(path: str) -> Iterator[sqlite3.Connection]:
    conn = _connect_db(path)
    conn.execute("PRAGMA foreign_keys = ON")
    if logger.isEnabledFor(logging.DEBUG):
        conn.set_trace_callback(lambda statement: logger.debug("SQL: %s", statement))
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


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


def _get_user_credentials(username: str) -> tuple[Optional[str], str]:
    path = _require_db_path()
    with _open_db(path) as conn:
        row = conn.execute(
            "SELECT password, role FROM users WHERE username = ?", (username,)
        ).fetchone()
    if not row:
        return None, ROLE_NORMAL
    return row[0], _normalize_role(row[1])


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
            host_id=host_id,
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
    return _backup_config_from_row(row)


def _backup_config_from_row(row: sqlite3.Row) -> BackupConfig:
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


def _load_backup_from_db_by_id(path: str, backup_id: str) -> BackupConfig:
    _ensure_db(path)
    with _open_db(path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT address, username, password, base_path, protocol, port "
            "FROM backups WHERE id = ?",
            (backup_id,),
        ).fetchone()
    if not row:
        raise ConfigError(f"Unknown backup id: {backup_id}")
    return _backup_config_from_row(row)


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


def _action_label(action: str) -> str:
    if action == "hard_restart":
        return "Hard restart"
    return action.capitalize()


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
                "SELECT host_id, project, enabled, last_backup_at, last_backup_success, last_backup_message, last_backup_failure "
                "FROM backup_state WHERE host_id = ?",
                (host_id,),
            ).fetchall()
        else:
            backup_rows = conn.execute(
                "SELECT host_id, project, enabled, last_backup_at, last_backup_success, last_backup_message, last_backup_failure "
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
                "last_backup_failure": row["last_backup_failure"],
                "last_backup_success": (
                    None
                    if row["last_backup_success"] is None
                    else bool(row["last_backup_success"])
                ),
                "last_backup_message": row["last_backup_message"],
                "last_backup_failure": row["last_backup_failure"],
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
                    "last_backup_failure": backup_info.get("last_backup_failure"),
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
                            f"UPDATE service_state SET status = ?, refreshed_at = ? "
                            f"WHERE host_id = ? AND project_id = ? AND id NOT IN ({placeholders})",
                            ("down", refreshed_at_str, host_id, project_id, *service_list),
                        )
                    else:
                        conn.execute(
                            "UPDATE service_state SET status = ?, refreshed_at = ? "
                            "WHERE host_id = ? AND project_id = ?",
                            ("down", refreshed_at_str, host_id, project_id),
                        )

                if not include_status and not include_updates:
                    continue
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
                f"UPDATE service_state SET status = ?, refreshed_at = ? "
                f"WHERE host_id = ? AND project_id = ? AND id NOT IN ({placeholders})",
                ("down", refreshed_at_str, host_id, project_id, *service_ids),
            )
        else:
            conn.execute(
                "UPDATE service_state SET status = ?, refreshed_at = ? "
                "WHERE host_id = ? AND project_id = ?",
                ("down", refreshed_at_str, host_id, project_id),
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


def _start_fd_track_task() -> Optional[asyncio.Task]:
    if FD_TRACK_INTERVAL_SECONDS <= 0:
        return None
    return asyncio.create_task(_fd_track_loop())


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
    try:
        _ensure_db(path, log_exception=False)
    except ConfigError as exc:
        logger.warning("Token cleanup skipped: %s", exc)
        return
    now = _now().isoformat()
    with _open_db(path) as conn:
        conn.execute(
            "DELETE FROM tokens WHERE expiration IS NOT NULL AND expiration < ?",
            (now,),
        )


async def _token_cleanup_loop() -> None:
    while True:
        run_at = _now()
        logger.debug("Event trigger token_cleanup")
        try:
            await asyncio.to_thread(_purge_expired_tokens)
            _record_event_result("token_cleanup", True, "Token cleanup complete", run_at)
        except Exception as exc:
            _record_event_result("token_cleanup", False, str(exc), run_at)
            logger.exception("Token cleanup failed")
        _set_event_next_run(
            "token_cleanup", run_at + timedelta(seconds=TOKEN_CLEANUP_INTERVAL_SECONDS)
        )
        await asyncio.sleep(TOKEN_CLEANUP_INTERVAL_SECONDS)


async def _fd_track_loop() -> None:
    interval = max(1, FD_TRACK_INTERVAL_SECONDS)
    while True:
        run_at = _now()
        logger.debug("Event trigger fd_track")
        try:
            summary = await asyncio.to_thread(_log_fd_usage)
            if summary:
                _record_event_result("fd_track", True, summary, run_at)
            else:
                _record_event_result("fd_track", False, "FD usage unavailable", run_at)
        except Exception as exc:
            _record_event_result("fd_track", False, str(exc), run_at)
            logger.debug("FD tracking failed: %s", exc)
        _set_event_next_run("fd_track", run_at + timedelta(seconds=interval))
        await asyncio.sleep(interval)



async def _set_state_interval(seconds: int) -> None:
    await _stop_state_task()
    app.state.state_interval_seconds = max(0, seconds)
    app.state.state_task = _start_state_task()
    if app.state.state_interval_seconds > 0:
        _set_event_next_run("status_refresh", _now() + timedelta(seconds=app.state.state_interval_seconds))
    else:
        _set_event_next_run("status_refresh", None)
    _persist_interval_setting("state_interval_seconds", app.state.state_interval_seconds)


async def _set_update_interval(seconds: int) -> None:
    await _stop_update_task()
    app.state.update_interval_seconds = max(0, seconds)
    app.state.update_task = _start_update_task()
    if app.state.update_interval_seconds > 0:
        _set_event_next_run("update_refresh", _now() + timedelta(seconds=app.state.update_interval_seconds))
    else:
        _set_event_next_run("update_refresh", None)
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






def _load_backup_state_rows() -> List[dict]:
    path = app.state.db_path
    if not path:
        return []
    _ensure_db(path)
    with _open_db(path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT host_id, project, enabled, cron_override, last_backup_at, last_backup_success, last_backup_failure "
            "FROM backup_state"
        ).fetchall()
    items = []
    for row in rows:
        last_backup_success = row["last_backup_success"]
        if last_backup_success is not None:
            last_backup_success = bool(last_backup_success)
        items.append(
            {
                "host_id": row["host_id"],
                "project": row["project"],
                "enabled": bool(row["enabled"]),
                "cron_override": row["cron_override"],
                "last_backup_at": _parse_timestamp(row["last_backup_at"]),
                "last_backup_success": last_backup_success,
                "last_backup_failure": row["last_backup_failure"],
            }
        )
    return items

def _global_backup_last_run(rows: List[dict]) -> Optional[datetime]:
    latest = None
    for row in rows:
        if not row.get("enabled"):
            continue
        if row.get("cron_override"):
            continue
        value = row.get("last_backup_at")
        if value and (latest is None or value > latest):
            latest = value
    return latest


def _build_backup_schedule_summary() -> List[BackupScheduleSummaryEntry]:
    cron_expr, cron_enabled = _load_backup_cron_state()
    rows = _load_backup_state_rows()
    now = _now()
    global_enabled = bool(cron_enabled and cron_expr)
    global_last_run = _global_backup_last_run(rows)
    global_next_run = None
    if global_enabled:
        base_time = global_last_run or now
        global_next_run = _next_cron_run(cron_expr, base_time)

    global_last_success = None
    global_last_failure = None
    if global_last_run:
        candidates = [
            row for row in rows
            if row.get("enabled") and not row.get("cron_override") and row.get("last_backup_at")
        ]
        if candidates:
            latest = max(candidates, key=lambda item: item["last_backup_at"])
            global_last_success = latest.get("last_backup_success")
            global_last_failure = latest.get("last_backup_failure")

    items: List[BackupScheduleSummaryEntry] = [
        BackupScheduleSummaryEntry(
            key="global",
            scope="global",
            name="global",
            last_run=global_last_run,
            last_success=global_last_success,
            last_failure=global_last_failure,
            next_run=global_next_run,
            enabled=global_enabled,
            override=False,
        )
    ]

    for row in sorted(rows, key=lambda item: (item["host_id"], item["project"])):
        host_id = row["host_id"]
        project = row["project"]
        key = f"{host_id}::{project}"
        enabled = bool(row.get("enabled"))
        override = bool(row.get("cron_override"))
        next_run = None
        if enabled:
            if override and row.get("cron_override"):
                base_time = row.get("last_backup_at") or now
                next_run = _next_cron_run(row["cron_override"], base_time)
            elif global_enabled and cron_expr:
                base_time = row.get("last_backup_at") or now
                next_run = _next_cron_run(cron_expr, base_time)
        items.append(
            BackupScheduleSummaryEntry(
                key=key,
                scope="project",
                name=project,
                host_id=host_id,
                project=project,
                last_run=row.get("last_backup_at"),
                last_success=row.get("last_backup_success"),
                last_failure=row.get("last_backup_failure"),
                next_run=next_run,
                enabled=enabled,
                override=override,
            )
        )

    return items
def _build_event_status_entries() -> List[EventStatusEntry]:
    now = _now()
    status_map = getattr(app.state, "event_status", {})
    events: List[EventStatusEntry] = []
    for key, info in EVENT_DEFINITIONS.items():
        data = status_map.get(key, {})
        last_run = data.get("last_run")
        last_success = data.get("last_success")
        last_result = data.get("last_result")
        next_run = data.get("next_run")
        interval = None
        enabled = True

        if key == "status_refresh":
            interval = app.state.state_interval_seconds
            enabled = interval > 0
        elif key == "update_refresh":
            interval = app.state.update_interval_seconds
            enabled = interval > 0 and compose.UPDATE_CHECKS_ENABLED
            if not compose.UPDATE_CHECKS_ENABLED and not last_result:
                last_result = "Update checks disabled"
        elif key == "backup_schedule":
            interval = None
            try:
                cron_expr, cron_enabled = _load_backup_cron_state()
                enabled_targets = _load_enabled_backups()
                enabled = (
                    bool(_config().backup)
                    and cron_enabled
                    and bool(cron_expr)
                    and bool(enabled_targets)
                )
            except Exception as exc:
                enabled = False
                if not last_result:
                    last_result = f"Backup schedule unavailable: {exc}"
            if not next_run:
                next_times = [
                    entry.get("next_run")
                    for entry in app.state.backup_schedule_map.values()
                    if entry.get("next_run")
                ]
                if next_times:
                    next_run = min(next_times)
        elif key == "token_cleanup":
            interval = TOKEN_CLEANUP_INTERVAL_SECONDS
            enabled = bool(app.state.db_path) and interval > 0
        elif key == "fd_track":
            interval = FD_TRACK_INTERVAL_SECONDS
            enabled = interval > 0

        if enabled and not next_run and interval:
            base = last_run or now
            next_run = base + timedelta(seconds=interval)
        if not enabled:
            next_run = None

        events.append(
            EventStatusEntry(
                id=key,
                label=info["label"],
                description=info["description"],
                enabled=enabled,
                next_run=next_run,
                last_run=last_run,
                last_success=last_success,
                last_result=last_result,
                interval_seconds=interval,
            )
        )

    return events


async def _run_scheduled_backup_for_project(host_id: str, project: str) -> str:
    backup = _backup_config()
    if await _backup_in_progress(host_id, project):
        logger.info(
            "Skipping scheduled backup (already running) host=%s project=%s",
            host_id,
            project,
        )
        return "skipped"
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
        return "success"
    except Exception as exc:
        await asyncio.to_thread(
            _record_backup_result, host_id, project, False, str(exc)
        )
        logger.exception(
            "Scheduled backup failed host=%s project=%s",
            host_id,
            project,
        )
        return "failed"


async def _backup_refresh_loop() -> None:
    schedule_event = app.state.backup_schedule_event
    while True:
        try:
            now = _now()
            logger.debug("Event trigger backup_schedule")
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
                _set_event_next_run("backup_schedule", None)
                schedule_event.clear()
                try:
                    await asyncio.wait_for(schedule_event.wait(), timeout=60)
                except asyncio.TimeoutError:
                    pass
                continue

            ran_any = False
            success_count = 0
            failure_count = 0
            skipped_count = 0
            for key, entry in list(schedule_map.items()):
                next_run = entry.get("next_run")
                if not next_run or next_run > now:
                    continue
                host_id, project = key.split("::", 1)
                status = await _run_scheduled_backup_for_project(host_id, project)
                ran_any = True
                if status == "success":
                    success_count += 1
                elif status == "failed":
                    failure_count += 1
                else:
                    skipped_count += 1
                cron_value = entry.get("cron")
                schedule_map[key]["next_run"] = (
                    _next_cron_run(cron_value, _now()) if cron_value else None
                )

            if ran_any:
                total = success_count + failure_count + skipped_count
                message = (
                    f"Ran {total} scheduled backup(s): {success_count} success, "
                    f"{failure_count} failed, {skipped_count} skipped"
                )
                _record_event_result(
                    "backup_schedule", failure_count == 0, message, now
                )

            next_times = [
                entry.get("next_run")
                for entry in schedule_map.values()
                if entry.get("next_run")
            ]
            if not next_times:
                _set_event_next_run("backup_schedule", None)
                await asyncio.sleep(60)
                continue
            next_run = min(next_times)
            _set_event_next_run("backup_schedule", next_run)
            sleep_seconds = max(30, (next_run - _now()).total_seconds())
            schedule_event.clear()
            try:
                await asyncio.wait_for(schedule_event.wait(), timeout=sleep_seconds)
            except asyncio.TimeoutError:
                pass
        except HTTPException:
            raise
        except Exception as exc:
            _record_event_result("backup_schedule", False, str(exc), _now())
            logger.exception("Scheduled backup run failed")
        await asyncio.sleep(60)


async def _state_refresh_loop() -> None:
    interval = app.state.state_interval_seconds
    if interval <= 0:
        return
    while True:
        run_at = _now()
        logger.debug("Event trigger status_refresh")
        try:
            await _refresh_status_candidate()
            _record_event_result(
                "status_refresh", True, "Status refresh cycle complete", run_at
            )
        except Exception as exc:
            _record_event_result("status_refresh", False, str(exc), run_at)
            logger.exception("Status state refresh failed")
        _set_event_next_run("status_refresh", run_at + timedelta(seconds=interval))
        await asyncio.sleep(interval)


async def _update_refresh_loop() -> None:
    interval = app.state.update_interval_seconds
    if interval <= 0:
        return
    while True:
        run_at = _now()
        logger.debug("Event trigger update_refresh")
        if not compose.UPDATE_CHECKS_ENABLED:
            _record_event_result(
                "update_refresh", None, "Update checks disabled", run_at
            )
            _set_event_next_run("update_refresh", run_at + timedelta(seconds=interval))
            await asyncio.sleep(interval)
            continue
        try:
            await _refresh_update_state()
            _record_event_result(
                "update_refresh", True, "Update check cycle complete", run_at
            )
        except Exception as exc:
            _record_event_result("update_refresh", False, str(exc), run_at)
            logger.exception("Update state refresh failed")
        _set_event_next_run("update_refresh", run_at + timedelta(seconds=interval))
        await asyncio.sleep(interval)






def _config() -> AppConfig:
    return app.state.config


def _host(host_id: str):
    try:
        host = get_host_config(_config(), host_id)
    except ConfigError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if not getattr(host, "host_id", None):
        host = host.model_copy(update={"host_id": host_id})
    return host


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


@app.get("/backup/targets", response_model=List[BackupTargetEntry])
def list_backup_targets() -> List[BackupTargetEntry]:
    path = _require_db_path()
    with _open_db(path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, enabled FROM backups ORDER BY id"
        ).fetchall()
    targets = []
    for row in rows:
        backup_id = row["id"]
        if not backup_id:
            continue
        enabled = True if row["enabled"] is None else bool(row["enabled"])
        targets.append(BackupTargetEntry(id=backup_id, enabled=enabled))
    return targets


@app.get("/backup/targets/{backup_id}/projects", response_model=BackupProjectsResponse)
def list_backup_projects(backup_id: str) -> BackupProjectsResponse:
    path = _require_db_path()
    try:
        backup = _load_backup_from_db_by_id(path, backup_id)
    except ConfigError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    try:
        projects = compose.list_backup_projects(backup)
    except Exception as exc:
        _handle_errors(exc)
    return BackupProjectsResponse(backup_id=backup_id, projects=projects)


@app.post("/backup/restore", response_model=List[OperationResponse])
def restore_backup(payload: BackupRestoreRequest) -> List[OperationResponse]:
    logger.debug("Action restore backup host_id=%s backup_id=%s projects=%s", payload.host_id, payload.backup_id, payload.projects or ([] if payload.project is None else [payload.project]))
    host = _host(payload.host_id)
    path = _require_db_path()
    try:
        backup = _load_backup_from_db_by_id(path, payload.backup_id)
    except ConfigError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    projects = payload.projects or ([] if payload.project is None else [payload.project])
    projects = [project for project in projects if project]
    if not projects:
        raise HTTPException(status_code=400, detail="No projects selected for restore.")
    if not payload.overwrite:
        existing = [project for project in projects if compose.project_exists(host, project)]
        if existing:
            raise HTTPException(
                status_code=409,
                detail="Projects already exist on the host: " + ", ".join(existing) + ". Confirm overwrite to restore.",
            )
    results: List[OperationResponse] = []
    for project in projects:
        running_before = False
        stop_message = None
        start_message = None
        try:
            if compose.project_exists(host, project):
                overall, containers, _ = compose.project_status(host, project)
                running_before = _is_project_running(overall, containers)
        except Exception:
            running_before = False
        if running_before:
            try:
                stop_result = compose.stop_project(host, project)
                if stop_result.stdout:
                    stop_message = stop_result.stdout.strip()
            except Exception as exc:
                stop_message = f"Stop failed: {exc}"
        try:
            dest, output = compose.restore_project(payload.host_id, host, project, backup)
            message = output or f"Restore complete: {dest}"
        except Exception as exc:
            message = f"Restore failed: {exc}"
        if running_before:
            try:
                start_result = compose.start_project(host, project)
                if start_result.stdout:
                    start_message = start_result.stdout.strip()
                else:
                    start_message = "Project started"
            except Exception as exc:
                start_message = f"Start failed: {exc}"
        extra_parts = []
        if stop_message:
            extra_parts.append(f"Stop: {stop_message}")
        if start_message:
            extra_parts.append(f"Start: {start_message}")
        if extra_parts:
            message = f"{message}\n" + "\n".join(extra_parts)
        results.append(
            OperationResponse(
                host_id=payload.host_id,
                project=project,
                action="restore",
                output=message,
            )
        )
    return results


@app.get("/config/users", response_model=List[UserConfigEntry])
def list_user_configs() -> List[UserConfigEntry]:
    path = _require_db_path()
    with _open_db(path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT username, last_login, role FROM users ORDER BY username"
        ).fetchall()
    return [
        UserConfigEntry(
            username=row["username"],
            last_login=_parse_db_datetime(row["last_login"]),
            role=_normalize_role(row["role"]),
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
    role = _normalize_role(entry.role)
    if username.lower() == "admin":
        role = ROLE_ADMIN
    password_hash = _hash_password(_secret_seed(), entry.password)
    path = _require_db_path()
    try:
        with _open_db(path) as conn:
            conn.execute(
                "INSERT INTO users (username, password, last_login, role) VALUES (?, ?, ?, ?)",
                (username, password_hash, None, role),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="User already exists.") from exc
    return UserConfigEntry(username=username, last_login=None, role=role)


@app.put("/config/users/{username}", response_model=UserConfigEntry)
def update_user_config(username: str, entry: UserUpdateRequest) -> UserConfigEntry:
    username = username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required.")
    password_hash = None
    if entry.password:
        password_hash = _hash_password(_secret_seed(), entry.password)
    role = None
    if entry.role is not None:
        role = _normalize_role(entry.role)
        if username.lower() == "admin":
            role = ROLE_ADMIN
    if password_hash is None and role is None:
        raise HTTPException(status_code=400, detail="Password or role is required.")
    path = _require_db_path()
    with _open_db(path) as conn:
        updates = []
        params = []
        if password_hash is not None:
            updates.append("password = ?")
            params.append(password_hash)
        if role is not None:
            updates.append("role = ?")
            params.append(role)
        params.append(username)
        result = conn.execute(
            f"UPDATE users SET {', '.join(updates)} WHERE username = ?",
            params,
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="User not found.")
        row = conn.execute(
            "SELECT last_login, role FROM users WHERE username = ?", (username,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found.")
    return UserConfigEntry(
        username=username,
        last_login=_parse_db_datetime(row[0]),
        role=_normalize_role(row[1]),
    )


@app.delete("/config/users/{username}", response_model=SimpleStatusResponse)
def delete_user_config(username: str) -> SimpleStatusResponse:
    username = username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required.")
    if username.lower() == "admin":
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
    logger.debug("Action list projects host_id=%s", host_id)
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
    backup_last_failure = {}
    backup_cron_override = {}
    for project in projects:
        info = backup_settings.get((host_id, project), {})
        backup_enabled[project] = info.get("enabled", False)
        backup_last_at[project] = info.get("last_backup_at")
        backup_last_success[project] = info.get("last_backup_success")
        backup_last_message[project] = info.get("last_backup_message")
        backup_last_failure[project] = info.get("last_backup_failure")
        backup_cron_override[project] = info.get("cron_override")

    return ProjectListResponse(
        host_id=host_id,
        projects=projects,
        project_paths=path_map,
        backup_enabled=backup_enabled,
        backup_last_at=backup_last_at,
        backup_last_success=backup_last_success,
        backup_last_message=backup_last_message,
        backup_last_failure=backup_last_failure,
        backup_cron_override=backup_cron_override,
    )


@app.post("/hosts/{host_id}/sleep", response_model=OperationResponse)
async def sleep_host(host_id: str) -> OperationResponse:
    logger.debug("Action sleep host host_id=%s", host_id)
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
    logger.debug("Action wake host host_id=%s", host_id)
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


@app.get("/hosts/{host_id}/projects/{project}/stats", response_model=ProjectStatsResponse)
def project_stats(host_id: str, project: str) -> ProjectStatsResponse:
    host = _host(host_id)
    try:
        stats = compose.project_stats(host, project)
    except Exception as exc:
        _handle_errors(exc)
    return ProjectStatsResponse(
        host_id=host_id,
        project=project,
        stats=[ProjectStatEntry(**item) for item in stats],
    )


@app.get("/hosts/{host_id}/projects/{project}/ports", response_model=ProjectPortsResponse)
def project_ports(host_id: str, project: str) -> ProjectPortsResponse:
    host = _host(host_id)
    try:
        ports = compose.project_ports(host, project)
    except Exception as exc:
        _handle_errors(exc)
    return ProjectPortsResponse(
        host_id=host_id,
        project=project,
        ports=[ProjectPortEntry(**item) for item in ports],
    )


@app.websocket("/ws/hosts/{host_id}/projects/{project}/services/{service}/shell")
async def service_shell(
    websocket: WebSocket, host_id: str, project: str, service: str
) -> None:
    header = websocket.headers.get("authorization")
    token = None
    if header:
        try:
            token = _extract_bearer_token(header)
        except HTTPException:
            token = None
    if not token:
        token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4401)
        return
    try:
        username, role = _verify_token_value(token)
    except HTTPException:
        await websocket.close(code=4401)
        return
    if role not in (ROLE_ADMIN, ROLE_POWER):
        await websocket.close(code=4403)
        return

    await websocket.accept()
    websocket.scope["username"] = username
    websocket.scope["user_role"] = role
    host = _host(host_id)
    try:
        container = compose.service_container(host, project, service)
    except Exception as exc:
        await websocket.send_text(f"error: {exc}")
        await websocket.close()
        return

    cols = int(websocket.query_params.get("cols", "80"))
    rows = int(websocket.query_params.get("rows", "24"))
    stop_event = threading.Event()
    loop = asyncio.get_running_loop()
    client = None
    channel = None
    command = f"docker exec -it {shlex.quote(container)} /bin/sh"

    try:
        client, channel = open_ssh_shell(host, command, cols=cols, rows=rows)
    except Exception as exc:
        await websocket.send_text(f"error: {exc}")
        await websocket.close()
        return

    def reader() -> None:
        try:
            while not stop_event.is_set():
                if channel.recv_ready():
                    data = channel.recv(4096)
                    if data:
                        asyncio.run_coroutine_threadsafe(websocket.send_bytes(data), loop)
                        continue
                if channel.recv_stderr_ready():
                    data = channel.recv_stderr(4096)
                    if data:
                        asyncio.run_coroutine_threadsafe(websocket.send_bytes(data), loop)
                        continue
                if channel.exit_status_ready():
                    break
                time.sleep(0.05)
        except Exception as exc:
            asyncio.run_coroutine_threadsafe(
                websocket.send_text(f"error: {exc}"), loop
            )
        finally:
            asyncio.run_coroutine_threadsafe(websocket.close(), loop)

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()

    try:
        while True:
            message = await websocket.receive_text()
            if not message:
                continue
            try:
                payload = json.loads(message)
            except json.JSONDecodeError:
                payload = {"type": "input", "data": message}
            if payload.get("type") == "resize":
                try:
                    resize_cols = int(payload.get("cols", cols))
                    resize_rows = int(payload.get("rows", rows))
                    channel.resize_pty(width=resize_cols, height=resize_rows)
                except (ValueError, TypeError, AttributeError):
                    pass
                continue
            data = payload.get("data", "")
            if data:
                try:
                    channel.send(data)
                except Exception:
                    break
    except WebSocketDisconnect:
        stop_event.set()
    finally:
        stop_event.set()
        if channel is not None:
            try:
                channel.close()
            except Exception:
                pass
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


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

    async def event_stream():
        queue: asyncio.Queue[Optional[tuple[str, str]]] = asyncio.Queue()
        stop_event = threading.Event()

        def worker() -> None:
            try:
                for stream, line in compose.stream_project_logs(
                    host, project, tail, service, stop_event, timeout=60
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


@app.post(
    "/hosts/{host_id}/projects/{project}/compose/command",
    response_model=ComposeCommandResponse,
)
async def run_compose_command_endpoint(
    host_id: str, project: str, payload: ComposeCommandRequest
) -> ComposeCommandResponse:
    host = _host(host_id)
    command = (payload.command or "").strip()
    if not command:
        raise HTTPException(status_code=400, detail="Command is required.")
    try:
        result = await asyncio.to_thread(
            compose.run_compose_command, host, project, command
        )
    except Exception as exc:
        _handle_errors(exc)
    return ComposeCommandResponse(
        host_id=host_id,
        project=project,
        command=command,
        exit_code=result.exit_code,
        stdout=result.stdout or "",
        stderr=result.stderr or "",
    )


@app.post("/auth/token", response_class=PlainTextResponse)
def create_auth_token(payload: AuthTokenRequest) -> str:
    username = payload.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required.")
    stored_password, role = _get_user_credentials(username)
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
        "role": role,
    }
    encoded = base64.b64encode(json.dumps(token_payload, separators=(",", ":")).encode()).decode()
    return encoded


@app.post("/auth/password", response_model=SimpleStatusResponse)
def change_password(request: Request, payload: PasswordChangeRequest) -> SimpleStatusResponse:
    username = getattr(request.state, "username", "")
    if not username:
        raise HTTPException(status_code=401, detail="Unauthorized.")
    if not payload.current_password or not payload.new_password:
        raise HTTPException(status_code=400, detail="Current and new password are required.")
    stored_password, _ = _get_user_credentials(username)
    if not stored_password:
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    provided = _hash_password(_secret_seed(), payload.current_password)
    if not hmac.compare_digest(stored_password, provided):
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    new_hash = _hash_password(_secret_seed(), payload.new_password)
    path = _require_db_path()
    with _open_db(path) as conn:
        conn.execute(
            "UPDATE users SET password = ? WHERE username = ?",
            (new_hash, username),
        )
    return SimpleStatusResponse(ok=True)


@app.get(
    "/hosts/{host_id}/projects/{project}/compose/command/stream",
    response_class=StreamingResponse,
)
async def stream_compose_command(
    host_id: str,
    project: str,
    request: Request,
    command: str = Query(..., min_length=1),
) -> StreamingResponse:
    host = _host(host_id)
    command = (command or "").strip()
    if not command:
        raise HTTPException(status_code=400, detail="Command is required.")
    async def event_stream():
        queue: asyncio.Queue[Optional[tuple[str, str]]] = asyncio.Queue()
        stop_event = threading.Event()

        def worker() -> None:
            try:
                for stream_name, line in compose.stream_compose_command(
                    host, project, command, stop_event, timeout=300
                ):
                    asyncio.run_coroutine_threadsafe(
                        queue.put((stream_name, line)), loop
                    )
            except Exception as exc:
                asyncio.run_coroutine_threadsafe(
                    queue.put(("error", str(exc))), loop
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
                stream_name, line = item
                if stream_name == "exit":
                    try:
                        exit_code = int(line)
                    except (TypeError, ValueError):
                        exit_code = 0
                    yield _sse_event("complete", {"exit_code": exit_code})
                    continue
                if stream_name == "error":
                    yield _sse_event("error", {"message": line})
                    continue
                event_name = stream_name if stream_name in ("stdout", "stderr") else "stdout"
                yield _sse_event(event_name, {"line": line})
        finally:
            stop_event.set()

    return StreamingResponse(event_stream(), media_type="text/event-stream")


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
def delete_project(host_id: str, project: str, delete_backup: bool = False) -> OperationResponse:
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
    if delete_backup:
        backup = _backup_config()
        try:
            compose.delete_backup_project(backup, project_name)
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
        output="Project deleted" + (" (backup deleted)" if delete_backup else ""),
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
    logger.debug("Action project stream host_id=%s project=%s action=%s", host_id, project, action)
    if action not in ("start", "stop", "restart", "hard_restart", "update"):
        raise HTTPException(status_code=400, detail="Unsupported action")
    stop_event = await _register_action_control(host_id, project, action)

    async def event_generator():
        try:
            action_label = _action_label(action)
            yield _sse_event(
                "step", {"step": "running", "message": f"Running {action_label}"}
            )
            updates_applied, _ = await asyncio.to_thread(
                compose.run_project_action_cancelable, host, project, action, stop_event
            )
            if action in ("start", "restart", "hard_restart"):
                await asyncio.to_thread(_set_project_sleeping, host_id, project, False)
            if action == "update":
                await asyncio.to_thread(
                    _mark_project_updates_current, host_id, project, _now()
                )
            payload = {"message": f"{action_label} complete"}
            if updates_applied is not None:
                payload["updates_applied"] = updates_applied
            yield _sse_event("complete", payload)
        except compose.ComposeCancelled:
            yield _sse_event(
                "complete",
                {"message": f"{action_label} cancelled", "stopped": True},
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
    logger.debug("Action project stop request host_id=%s project=%s action=%s", host_id, project, action)
    if action not in ("start", "stop", "restart", "hard_restart", "update"):
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
    logger.debug("Action project start host_id=%s project=%s", host_id, project)
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
    logger.debug("Action project stop host_id=%s project=%s", host_id, project)
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
    logger.debug("Action project restart host_id=%s project=%s", host_id, project)
    host = _host(host_id)
    try:
        result = compose.restart_project(host, project)
    except Exception as exc:
        _handle_errors(exc)
    return OperationResponse(
        host_id=host_id, project=project, action="restart", output=result.stdout
    )


@app.post("/hosts/{host_id}/projects/{project}/hard_restart", response_model=OperationResponse)
def hard_restart_project(host_id: str, project: str) -> OperationResponse:
    logger.debug("Action project hard restart host_id=%s project=%s", host_id, project)
    host = _host(host_id)
    try:
        output = compose.hard_restart_project(host, project)
        _set_project_sleeping(host_id, project, False)
    except Exception as exc:
        _handle_errors(exc)
    return OperationResponse(
        host_id=host_id, project=project, action="hard_restart", output=output
    )


@app.post("/hosts/{host_id}/projects/{project}/backup", response_model=OperationResponse)
def backup_project(host_id: str, project: str) -> OperationResponse:
    logger.debug("Action project backup host_id=%s project=%s", host_id, project)
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
    logger.debug("Action project backup stream host_id=%s project=%s", host_id, project)
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
    logger.debug("Action backup stop request host_id=%s project=%s", host_id, project)
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
        last_backup_failure=info.get("last_backup_failure"),
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
        last_backup_failure=info.get("last_backup_failure"),
        cron_override=cron_override,
        effective_cron=effective_cron,
        next_run=next_run,
    )


@app.post(
    "/hosts/{host_id}/projects/{project}/services/{service}/start",
    response_model=OperationResponse,
)
def start_service(host_id: str, project: str, service: str) -> OperationResponse:
    logger.debug("Action service start host_id=%s project=%s service=%s", host_id, project, service)
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
    logger.debug("Action service stream host_id=%s project=%s service=%s action=%s", host_id, project, service, action)
    if action not in ("start", "stop", "restart", "hard_restart"):
        raise HTTPException(status_code=400, detail="Unsupported action")
    stop_event = await _register_service_action_control(
        host_id, project, service, action
    )

    async def event_generator():
        try:
            action_label = _action_label(action)
            yield _sse_event(
                "step", {"step": "running", "message": f"Running {action_label}"}
            )
            await asyncio.to_thread(
                compose.run_service_action_cancelable,
                host,
                project,
                service,
                action,
                stop_event,
            )
            payload = {"message": f"{action_label} complete"}
            yield _sse_event("complete", payload)
        except compose.ComposeCancelled:
            yield _sse_event(
                "complete",
                {"message": f"{action_label} cancelled", "stopped": True},
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
    logger.debug("Action service stop request host_id=%s project=%s service=%s action=%s", host_id, project, service, action)
    if action not in ("start", "stop", "restart", "hard_restart"):
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
    logger.debug("Action service stop host_id=%s project=%s service=%s", host_id, project, service)
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
    logger.debug("Action service restart host_id=%s project=%s service=%s", host_id, project, service)
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
    logger.debug("Action project check updates host_id=%s project=%s", host_id, project)
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
    logger.debug("Action project apply updates host_id=%s project=%s", host_id, project)
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


@app.get("/events/status", response_model=EventStatusResponse)
async def get_event_status() -> EventStatusResponse:
    events = await asyncio.to_thread(_build_event_status_entries)
    return EventStatusResponse(generated_at=_now(), events=events)


@app.post(
    "/hosts/{host_id}/projects/{project}/state/refresh",
    response_model=StateRefreshResponse,
)
async def refresh_project_state_endpoint(
    host_id: str, project: str
) -> StateRefreshResponse:
    _host(host_id)
    logger.debug("Action refresh project state host_id=%s project=%s", host_id, project)
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


@app.get("/backup/schedule/summary", response_model=BackupScheduleSummaryResponse)
async def get_backup_schedule_summary() -> BackupScheduleSummaryResponse:
    items = await asyncio.to_thread(_build_backup_schedule_summary)
    return BackupScheduleSummaryResponse(items=items)


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
    logger.debug("Action refresh host state host_id=%s", host_id)
    refreshed_at = await _refresh_status_state([host_id])
    return StateRefreshResponse(refreshed_at=refreshed_at)
