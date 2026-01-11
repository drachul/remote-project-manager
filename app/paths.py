import os
import re
from pathlib import Path

CONFIG_PATH_ENV = "CONFIG_PATH"
DEFAULT_CONFIG_PATH = "/config"
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def config_path() -> Path:
    value = os.environ.get(CONFIG_PATH_ENV, DEFAULT_CONFIG_PATH) or DEFAULT_CONFIG_PATH
    return Path(value).expanduser()


def keys_dir() -> Path:
    return config_path() / "keys"


def ensure_config_dirs() -> None:
    config_path().mkdir(parents=True, exist_ok=True)
    keys_dir().mkdir(parents=True, exist_ok=True)


def _safe_host_name(host_id: str) -> str:
    safe = _SAFE_NAME_RE.sub("_", host_id.strip())
    return safe or "host"


def host_key_path(host_id: str) -> Path:
    return keys_dir() / f"{_safe_host_name(host_id)}.key"


def _normalize_key_text(key_text: str) -> str:
    text = key_text.strip()
    text = text.replace("\\n", "\n")
    text = text.replace("\r\n", "\n")
    if not text.endswith("\n"):
        text += "\n"
    return text

def write_host_key(host_id: str, key_text: str) -> Path:
    ensure_config_dirs()
    path = host_key_path(host_id)
    normalized = _normalize_key_text(key_text)
    path.write_text(normalized, encoding="utf-8")
    os.chmod(path, 0o600)
    return path

def delete_host_key(host_id: str) -> None:
    path = host_key_path(host_id)
    try:
        if path.exists():
            path.unlink()
    except OSError:
        pass

