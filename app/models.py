from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class HostInfo(BaseModel):
    host_id: str
    host: str
    user: str
    project_root: str
    port: int


class HostConfigEntry(BaseModel):
    id: str
    project_root: str
    ssh_address: str
    ssh_username: str
    ssh_key: str
    ssh_port: int = 22


class BackupConfigEntry(BaseModel):
    id: str
    address: str
    username: str
    password: str
    base_path: str
    protocol: str = "ssh"
    port: int = 22
    enabled: bool = True


class SimpleStatusResponse(BaseModel):
    ok: bool


class ProjectListResponse(BaseModel):
    host_id: str
    projects: List[str]
    project_paths: Dict[str, str] = Field(default_factory=dict)
    backup_enabled: Dict[str, bool] = Field(default_factory=dict)
    backup_last_at: Dict[str, Optional[datetime]] = Field(default_factory=dict)
    backup_last_success: Dict[str, Optional[bool]] = Field(default_factory=dict)
    backup_last_message: Dict[str, Optional[str]] = Field(default_factory=dict)
    backup_cron_override: Dict[str, Optional[str]] = Field(default_factory=dict)


class LogsResponse(BaseModel):
    host_id: str
    project: str
    logs: str


class ContainerStatus(BaseModel):
    name: str
    service: Optional[str] = None
    state: str
    status: str
    exit_code: Optional[int]


class ProjectStatusResponse(BaseModel):
    host_id: str
    project: str
    overall_status: str
    containers: List[ContainerStatus]
    issues: List[str]


class ProjectStatEntry(BaseModel):
    service: str
    name: str
    cpu_percent: Optional[str] = None
    mem_usage: Optional[str] = None
    mem_percent: Optional[str] = None
    net_io: Optional[str] = None
    block_io: Optional[str] = None
    pids: Optional[int] = None
    uptime_seconds: Optional[int] = None
    restarts: Optional[int] = None


class ProjectStatsResponse(BaseModel):
    host_id: str
    project: str
    stats: List[ProjectStatEntry]


class ProjectPortEntry(BaseModel):
    service: str
    name: str
    container_port: Optional[str] = None
    protocol: Optional[str] = None
    host_ip: Optional[str] = None
    host_port: Optional[str] = None


class ProjectPortsResponse(BaseModel):
    host_id: str
    project: str
    ports: List[ProjectPortEntry]


class OperationResponse(BaseModel):
    host_id: str
    project: str
    action: str
    output: str


class AuthTokenRequest(BaseModel):
    username: str
    password: str


class UserConfigEntry(BaseModel):
    username: str
    last_login: Optional[datetime] = None


class UserCreateRequest(BaseModel):
    username: str
    password: str


class UserUpdateRequest(BaseModel):
    password: Optional[str] = None


class RunToComposeRequest(BaseModel):
    command: str
    service: Optional[str] = None


class RunToComposeResponse(BaseModel):
    compose: str
    service: str


class UpdateCheckResponse(BaseModel):
    host_id: str
    project: str
    supported: bool
    updates_available: bool
    details: str
    per_service: Dict[str, str] = Field(default_factory=dict)


class UpdateApplyResponse(BaseModel):
    host_id: str
    project: str
    updates_applied: bool
    output: str


class ComposeFileResponse(BaseModel):
    host_id: str
    project: str
    path: str
    content: str


class ComposeFileUpdateRequest(BaseModel):
    content: str


class ComposeValidateRequest(BaseModel):
    content: str


class ComposeValidateResponse(BaseModel):
    ok: bool
    output: str


class ComposeCommandRequest(BaseModel):
    command: str


class ComposeCommandResponse(BaseModel):
    host_id: str
    project: str
    command: str
    exit_code: int
    stdout: str = ""
    stderr: str = ""


class ProjectCreateRequest(BaseModel):
    project: str
    content: str
    enable_backup: bool = False


class ProjectCreateResponse(BaseModel):
    host_id: str
    project: str
    path: str
    backup_enabled: bool


class ServiceStateEntry(BaseModel):
    id: str
    status: Optional[str] = None
    update_available: bool = False
    refreshed_at: Optional[datetime] = None
    update_checked_at: Optional[datetime] = None


class ProjectStateEntry(BaseModel):
    project: str
    path: str
    overall_status: Optional[str] = None
    updates_available: bool = False
    sleeping: bool = False
    refreshed_at: Optional[datetime] = None
    backup_enabled: bool = False
    last_backup_at: Optional[datetime] = None
    last_backup_success: Optional[bool] = None
    last_backup_message: Optional[str] = None
    services: List[ServiceStateEntry] = Field(default_factory=list)


class HostStateResponse(BaseModel):
    host_id: str
    refreshed_at: Optional[datetime] = None
    projects: List[ProjectStateEntry] = Field(default_factory=list)


class StateResponse(BaseModel):
    refreshed_at: Optional[datetime] = None
    updates_enabled: bool = True
    hosts: List[HostStateResponse] = Field(default_factory=list)


class StateRefreshResponse(BaseModel):
    refreshed_at: datetime


class IntervalRequest(BaseModel):
    seconds: int


class IntervalResponse(BaseModel):
    seconds: int


class BackupSettingsRequest(BaseModel):
    enabled: Optional[bool] = None
    cron_override: Optional[str] = None


class BackupSettingsResponse(BaseModel):
    host_id: str
    project: str
    enabled: bool
    last_backup_at: Optional[datetime] = None
    last_backup_success: Optional[bool] = None
    last_backup_message: Optional[str] = None
    cron_override: Optional[str] = None
    effective_cron: Optional[str] = None
    next_run: Optional[datetime] = None


class BackupScheduleRequest(BaseModel):
    cron: Optional[str] = None
    enabled: Optional[bool] = None


class BackupScheduleResponse(BaseModel):
    cron: Optional[str] = None
    enabled: bool = False
    next_run: Optional[datetime] = None


class EventStatusEntry(BaseModel):
    id: str
    label: str
    description: str
    enabled: bool = True
    next_run: Optional[datetime] = None
    last_run: Optional[datetime] = None
    last_success: Optional[bool] = None
    last_result: Optional[str] = None
    interval_seconds: Optional[int] = None


class EventStatusResponse(BaseModel):
    generated_at: datetime
    events: List[EventStatusEntry] = Field(default_factory=list)


class BackupScheduleSummaryEntry(BaseModel):
    key: str
    scope: str
    name: str
    host_id: Optional[str] = None
    project: Optional[str] = None
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    enabled: bool = False
    override: bool = False


class BackupScheduleSummaryResponse(BaseModel):
    items: List[BackupScheduleSummaryEntry] = Field(default_factory=list)
