import os
from typing import Dict, Optional

from pydantic import BaseModel, Field, ValidationError


class HostConfig(BaseModel):
    host: str
    user: str
    ssh_key: Optional[str] = Field(
        None, description="Private SSH key content (not a file path)"
    )
    ssh_key_path: Optional[str] = Field(
        None, description="Path to private SSH key (legacy)"
    )
    project_root: str = Field(..., description="Remote root containing compose projects")
    port: int = 22


class BackupConfig(BaseModel):
    host: str
    user: str
    password: str = Field(..., description="Backup server SSH password")
    base_path: str = Field(..., description="Base path for backups on backup server")
    port: int = 22
    protocol: str = Field("ssh", description="Backup protocol: ssh or rsync")


class AppConfig(BaseModel):
    hosts: Dict[str, HostConfig] = Field(default_factory=dict)
    backup: Optional[BackupConfig] = None
    db_path: Optional[str] = Field(
        None, description="SQLite DB path for state and settings"
    )
    log_level: Optional[str] = Field(
        None, description="Logging level (e.g. DEBUG, INFO, WARNING)"
    )


class ConfigError(RuntimeError):
    pass


def load_config(path: Optional[str] = None) -> AppConfig:
    db_path = os.environ.get("DB_PATH")
    log_level = os.environ.get("APP_LOG_LEVEL")
    try:
        return AppConfig.model_validate({"db_path": db_path, "log_level": log_level})
    except ValidationError as exc:
        raise ConfigError(f"Invalid environment configuration: {exc}") from exc


def get_host_config(config: AppConfig, host_id: str) -> HostConfig:
    try:
        return config.hosts[host_id]
    except KeyError as exc:
        raise ConfigError(f"Unknown host id: {host_id}") from exc
