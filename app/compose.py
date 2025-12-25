import json
import re
import shlex
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from .config import BackupConfig, HostConfig
from .ssh import (
    SSHCancelled,
    SSHError,
    SSHResult,
    read_remote_file,
    run_ssh_command,
    run_ssh_command_cancelable,
    write_remote_file,
)


class ComposeError(RuntimeError):
    pass


class ComposeCancelled(RuntimeError):
    pass


COMPOSE_FILENAMES = (
    "compose.yaml",
    "compose.yml",
    "docker-compose.yml",
    "docker-compose.yaml",
)

UPDATE_CHECKS_ENABLED = False

_SAFE_KEY_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def _sanitize_service_name(value: Optional[str]) -> str:
    if not value:
        return "app"
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip().lower())
    normalized = normalized.strip("-._")
    return normalized or "app"


def _yaml_quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")
    return f"\"{escaped}\""


def _yaml_key(value: str) -> str:
    if _SAFE_KEY_RE.match(value):
        return value
    return _yaml_quote(value)


def _yaml_inline_list(values: List[str]) -> str:
    return f"[{', '.join(_yaml_key(value) for value in values)}]"


def _append_yaml_list(lines: List[str], key: str, values: List[str]) -> None:
    if not values:
        return
    lines.append(f"    {key}:")
    for item in values:
        lines.append(f"      - {_yaml_quote(item)}")


def _append_yaml_mapping(lines: List[str], key: str, values: Dict[str, str]) -> None:
    if not values:
        return
    lines.append(f"    {key}:")
    for map_key, map_value in values.items():
        lines.append(f"      {_yaml_key(map_key)}: {_yaml_quote(map_value)}")


def _parse_gpus(value: str) -> Dict[str, object]:
    value = value.strip()
    if not value:
        return {}
    if value == "all":
        return {"count": "all"}
    params: Dict[str, object] = {}
    if "=" in value:
        parts = [part.strip() for part in value.split(",") if part.strip()]
        for part in parts:
            if "=" in part:
                key, val = part.split("=", 1)
                params[key.strip()] = val.strip()
            else:
                caps = params.setdefault("capabilities", [])
                if isinstance(caps, list):
                    caps.append(part)
    else:
        if value.isdigit():
            params["count"] = int(value)
        else:
            params["count"] = value
    device_value = params.pop("device", None) or params.get("device_ids")
    if device_value:
        device_ids = [item for item in str(device_value).split(",") if item]
        params["device_ids"] = device_ids
        if "count" not in params:
            params["count"] = len(device_ids)
    capabilities = params.get("capabilities")
    if not capabilities:
        params["capabilities"] = ["gpu"]
    elif isinstance(capabilities, str):
        params["capabilities"] = [capabilities]
    return params


def _consume_value(tokens: List[str], index: int, option: str, allow_concat: bool = False) -> Tuple[Optional[str], int]:
    token = tokens[index]
    if token == option:
        if index + 1 >= len(tokens):
            raise ComposeError(f"Missing value for {option}")
        return tokens[index + 1], 2
    if token.startswith(f"{option}="):
        return token.split("=", 1)[1], 1
    if allow_concat and token.startswith(option) and len(token) > len(option):
        return token[len(option) :], 1
    return None, 0


def _parse_mount(value: str) -> Tuple[Optional[str], Optional[str]]:
    params: Dict[str, str] = {}
    readonly = False
    for part in value.split(","):
        if "=" in part:
            key, val = part.split("=", 1)
            params[key.strip()] = val.strip()
        else:
            if part.strip() in ("ro", "readonly"):
                readonly = True
    mount_type = params.get("type", "bind")
    source = params.get("source") or params.get("src") or params.get("from")
    target = params.get("target") or params.get("dst") or params.get("destination")
    if not target:
        return None, None
    if mount_type == "tmpfs":
        return None, target
    if source:
        volume = f"{source}:{target}"
    else:
        volume = target
    if readonly:
        volume = f"{volume}:ro"
    return volume, None


def docker_run_to_compose(command: str, service_name: Optional[str] = None) -> Tuple[str, str]:
    tokens = shlex.split(command)
    if not tokens:
        raise ComposeError("Docker run command is empty.")
    if tokens[0] in ("docker", "podman"):
        tokens = tokens[1:]
        if tokens and tokens[0] == "container":
            tokens = tokens[1:]
        if tokens and tokens[0] == "run":
            tokens = tokens[1:]
    elif tokens[0] == "run":
        tokens = tokens[1:]

    if not tokens:
        raise ComposeError("Docker run command is missing an image.")

    image: Optional[str] = None
    container_name: Optional[str] = None
    ports: List[str] = []
    expose: List[str] = []
    environment: List[str] = []
    env_files: List[str] = []
    volumes: List[str] = []
    labels: Dict[str, str] = {}
    log_options: Dict[str, str] = {}
    extra_hosts: List[str] = []
    devices: List[str] = []
    dns: List[str] = []
    tmpfs: List[str] = []
    cap_add: List[str] = []
    cap_drop: List[str] = []
    gpu_request: Dict[str, object] = {}
    command_args: List[str] = []
    entrypoint: Optional[str] = None
    platform: Optional[str] = None
    cpus: Optional[str] = None
    restart: Optional[str] = None
    network: Optional[str] = None
    hostname: Optional[str] = None
    user: Optional[str] = None
    workdir: Optional[str] = None
    privileged = False
    tty = False
    stdin_open = False

    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            index += 1
            if image is None and index < len(tokens):
                image = tokens[index]
                command_args = tokens[index + 1 :]
            else:
                command_args = tokens[index:]
            break

        if image is None and token.startswith("-"):
            if token in ("-it", "-ti"):
                tty = True
                stdin_open = True
                index += 1
                continue
            if token.startswith("-") and not token.startswith("--") and len(token) > 2:
                short_flags = token[1:]
                if all(flag in "itd" for flag in short_flags):
                    tty = tty or "t" in short_flags
                    stdin_open = stdin_open or "i" in short_flags
                    index += 1
                    continue
            if token in ("-d", "--detach", "--rm"):
                index += 1
                continue
            if token in ("-t", "--tty"):
                tty = True
                index += 1
                continue
            if token in ("-i", "--interactive"):
                stdin_open = True
                index += 1
                continue
            value, consumed = _consume_value(tokens, index, "--name")
            if consumed:
                container_name = value
                index += consumed
                continue
            value, consumed = _consume_value(tokens, index, "--hostname")
            if consumed:
                hostname = value
                index += consumed
                continue
            value, consumed = _consume_value(tokens, index, "--restart")
            if consumed:
                restart = value
                index += consumed
                continue
            value, consumed = _consume_value(tokens, index, "--network")
            if not consumed:
                value, consumed = _consume_value(tokens, index, "--net")
            if consumed:
                network = value
                index += consumed
                continue
            value, consumed = _consume_value(tokens, index, "--entrypoint")
            if consumed:
                entrypoint = value
                index += consumed
                continue
            value, consumed = _consume_value(tokens, index, "--platform")
            if consumed:
                platform = value
                index += consumed
                continue
            value, consumed = _consume_value(tokens, index, "--cpus")
            if consumed:
                cpus = value
                index += consumed
                continue
            value, consumed = _consume_value(tokens, index, "--user")
            if consumed:
                user = value
                index += consumed
                continue
            value, consumed = _consume_value(tokens, index, "--workdir")
            if not consumed:
                value, consumed = _consume_value(tokens, index, "-w", allow_concat=True)
            if consumed:
                workdir = value
                index += consumed
                continue
            value, consumed = _consume_value(tokens, index, "--env-file")
            if consumed:
                env_files.append(value)
                index += consumed
                continue
            value, consumed = _consume_value(tokens, index, "--env")
            if not consumed:
                value, consumed = _consume_value(tokens, index, "-e", allow_concat=True)
            if consumed:
                environment.append(value)
                index += consumed
                continue
            value, consumed = _consume_value(tokens, index, "--publish")
            if not consumed:
                value, consumed = _consume_value(tokens, index, "-p", allow_concat=True)
            if consumed:
                ports.append(value)
                index += consumed
                continue
            value, consumed = _consume_value(tokens, index, "--expose")
            if consumed:
                expose.extend([item for item in value.split(",") if item])
                index += consumed
                continue
            value, consumed = _consume_value(tokens, index, "--volume")
            if not consumed:
                value, consumed = _consume_value(tokens, index, "-v", allow_concat=True)
            if consumed:
                volumes.append(value)
                index += consumed
                continue
            value, consumed = _consume_value(tokens, index, "--mount")
            if consumed:
                volume, tmpfs_target = _parse_mount(value)
                if volume:
                    volumes.append(volume)
                if tmpfs_target:
                    tmpfs.append(tmpfs_target)
                index += consumed
                continue
            value, consumed = _consume_value(tokens, index, "--label")
            if not consumed:
                value, consumed = _consume_value(tokens, index, "-l", allow_concat=True)
            if consumed:
                if "=" in value:
                    key, val = value.split("=", 1)
                    labels[key] = val
                else:
                    labels[value] = ""
                index += consumed
                continue
            value, consumed = _consume_value(tokens, index, "--log-opt")
            if consumed:
                if "=" in value:
                    key, val = value.split("=", 1)
                    log_options[key] = val
                else:
                    log_options[value] = ""
                index += consumed
                continue
            value, consumed = _consume_value(tokens, index, "--add-host")
            if consumed:
                extra_hosts.append(value)
                index += consumed
                continue
            value, consumed = _consume_value(tokens, index, "--device")
            if consumed:
                devices.append(value)
                index += consumed
                continue
            value, consumed = _consume_value(tokens, index, "--dns")
            if consumed:
                dns.append(value)
                index += consumed
                continue
            value, consumed = _consume_value(tokens, index, "--tmpfs")
            if consumed:
                tmpfs.append(value)
                index += consumed
                continue
            value, consumed = _consume_value(tokens, index, "--gpus")
            if consumed:
                gpu_request = _parse_gpus(value or "")
                index += consumed
                continue
            value, consumed = _consume_value(tokens, index, "--cap-add")
            if consumed:
                cap_add.append(value)
                index += consumed
                continue
            value, consumed = _consume_value(tokens, index, "--cap-drop")
            if consumed:
                cap_drop.append(value)
                index += consumed
                continue
            if token == "--privileged":
                privileged = True
                index += 1
                continue
            index += 1
            continue

        if image is None:
            image = token
            command_args = tokens[index + 1 :]
            break
        command_args = tokens[index:]
        break

    if image is None:
        raise ComposeError("Docker run command is missing an image.")

    service = _sanitize_service_name(service_name or container_name)

    lines = ["services:", f"  {service}:"]
    lines.append(f"    image: {_yaml_quote(image)}")
    if platform:
        lines.append(f"    platform: {_yaml_quote(platform)}")
    if container_name:
        lines.append(f"    container_name: {_yaml_quote(container_name)}")
    if entrypoint:
        lines.append(f"    entrypoint: {_yaml_quote(entrypoint)}")
    if command_args:
        lines.append("    command:")
        for arg in command_args:
            lines.append(f"      - {_yaml_quote(arg)}")
    _append_yaml_list(lines, "ports", ports)
    _append_yaml_list(lines, "expose", expose)
    _append_yaml_list(lines, "environment", environment)
    if env_files:
        _append_yaml_list(lines, "env_file", env_files)
    _append_yaml_list(lines, "volumes", volumes)
    if restart:
        lines.append(f"    restart: {_yaml_quote(restart)}")
    if network:
        if network in ("host", "bridge", "none"):
            lines.append(f"    network_mode: {_yaml_quote(network)}")
        else:
            lines.append("    networks:")
            lines.append(f"      - {_yaml_quote(network)}")
    if gpu_request:
        driver = gpu_request.get("driver") or "nvidia"
        lines.append(f"    runtime: {_yaml_quote(str(driver))}")

    if cpus or gpu_request:
        lines.append("    deploy:")
        lines.append("      resources:")
        if cpus:
            lines.append("        limits:")
            lines.append(f"          cpus: {_yaml_key(str(cpus))}")
        if gpu_request:
            lines.append("        reservations:")
            lines.append("          devices:")
            lines.append("            -")
            if driver:
                lines.append(f"              driver: {_yaml_quote(str(driver))}")
            if "count" in gpu_request:
                count_value = gpu_request["count"]
                if isinstance(count_value, int):
                    lines.append(f"              count: {count_value}")
                else:
                    lines.append(f"              count: {_yaml_key(str(count_value))}")
            capabilities = gpu_request.get("capabilities")
            if capabilities:
                caps = (
                    [str(item) for item in capabilities]
                    if isinstance(capabilities, list)
                    else [str(capabilities)]
                )
                lines.append(f"              capabilities: {_yaml_inline_list(caps)}")
            device_ids = gpu_request.get("device_ids")
            if device_ids:
                lines.append("              device_ids:")
                for device_id in device_ids:
                    lines.append(f"                - {_yaml_quote(str(device_id))}")
    _append_yaml_mapping(lines, "labels", labels)
    if log_options:
        lines.append("    logging:")
        lines.append("      options:")
        for key, val in log_options.items():
            lines.append(f"        {_yaml_key(key)}: {_yaml_quote(val)}")
    if hostname:
        lines.append(f"    hostname: {_yaml_quote(hostname)}")
    if user:
        lines.append(f"    user: {_yaml_quote(user)}")
    if workdir:
        lines.append(f"    working_dir: {_yaml_quote(workdir)}")
    if privileged:
        lines.append("    privileged: true")
    _append_yaml_list(lines, "cap_add", cap_add)
    _append_yaml_list(lines, "cap_drop", cap_drop)
    _append_yaml_list(lines, "devices", devices)
    _append_yaml_list(lines, "dns", dns)
    _append_yaml_list(lines, "extra_hosts", extra_hosts)
    _append_yaml_list(lines, "tmpfs", tmpfs)
    if tty:
        lines.append("    tty: true")
    if stdin_open:
        lines.append("    stdin_open: true")

    if network and network not in ("host", "bridge", "none"):
        lines.append("networks:")
        lines.append(f"  {_yaml_key(network)}:")
        lines.append("    external: true")

    return "\n".join(lines) + "\n", service


def _project_dir(host: HostConfig, project: str) -> str:
    return f"{host.project_root.rstrip('/')}/{project}"


def _compose_command(project_dir: str, args: List[str]) -> str:
    project_q = shlex.quote(project_dir)
    args_q = " ".join(shlex.quote(arg) for arg in args)
    return f"cd {project_q} && docker compose {args_q}"


def _run_compose(host: HostConfig, project: str, args: List[str], timeout: int = 120) -> SSHResult:
    command = _compose_command(_project_dir(host, project), args)
    result = run_ssh_command(host, command, timeout=timeout)
    if result.exit_code != 0:
        message = result.stderr or result.stdout or "Unknown error"
        raise ComposeError(message)
    return result


def _run_compose_cancelable(
    host: HostConfig,
    project: str,
    args: List[str],
    stop_event,
    timeout: int = 120,
) -> SSHResult:
    if stop_event.is_set():
        raise ComposeCancelled("Compose action cancelled")
    command = _compose_command(_project_dir(host, project), args)
    try:
        result = run_ssh_command_cancelable(host, command, stop_event, timeout=timeout)
    except SSHCancelled as exc:
        raise ComposeCancelled(str(exc)) from exc
    if result.exit_code != 0:
        message = result.stderr or result.stdout or "Unknown error"
        raise ComposeError(message)
    return result


def list_projects(host: HostConfig) -> List[str]:
    root_q = shlex.quote(host.project_root)
    command = (
        "find {root} -maxdepth 2 -mindepth 2 -type f "
        "\\( -name 'compose.yaml' -o -name 'compose.yml' -o -name 'docker-compose.yml' -o -name 'docker-compose.yaml' \\) "
        "-exec dirname {{}} \\; | sort -u"
    ).format(root=root_q)
    result = run_ssh_command(host, command)
    if result.exit_code != 0:
        message = result.stderr or result.stdout or "Unknown error"
        raise ComposeError(message)
    if not result.stdout:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def get_compose_file_path(host: HostConfig, project: str) -> str:
    project_dir = _project_dir(host, project)
    project_q = shlex.quote(project_dir)
    filenames = " ".join(COMPOSE_FILENAMES)
    command = (
        f"cd {project_q} && "
        f"for f in {filenames}; do "
        "if [ -f \"$f\" ]; then echo \"$f\"; break; fi; "
        "done"
    )
    result = run_ssh_command(host, command)
    if result.exit_code != 0:
        message = result.stderr or result.stdout or "Unknown error"
        raise ComposeError(message)
    filename = result.stdout.strip().splitlines()[0] if result.stdout else ""
    if not filename:
        raise ComposeError("Compose file not found")
    return f"{project_dir}/{filename}"


def read_compose_file(host: HostConfig, project: str) -> Tuple[str, str]:
    path = get_compose_file_path(host, project)
    content = read_remote_file(host, path)
    return path, content


def write_compose_file(host: HostConfig, project: str, content: str) -> str:
    path = get_compose_file_path(host, project)
    write_remote_file(host, path, content)
    return path


def validate_compose_content(host: HostConfig, project: str, content: str) -> Tuple[bool, str]:
    project_dir = _project_dir(host, project)
    temp_name = f".compose-manager-{uuid.uuid4().hex}.yaml"
    temp_path = f"{project_dir}/{temp_name}"
    cleanup_command = f"cd {shlex.quote(project_dir)} && rm -f {shlex.quote(temp_name)}"

    try:
        write_remote_file(host, temp_path, content)
        command = _compose_command(project_dir, ["-f", temp_name, "config"])
        result = run_ssh_command(host, command, timeout=120)
        output = "\n".join([result.stdout, result.stderr]).strip()
        return result.exit_code == 0, output
    finally:
        try:
            run_ssh_command(host, cleanup_command)
        except SSHError:
            pass


def validate_compose_content_temp(host: HostConfig, content: str) -> Tuple[bool, str]:
    temp_dir = f"/tmp/compose-manager-{uuid.uuid4().hex}"
    temp_name = "docker-compose.yml"
    temp_path = f"{temp_dir}/{temp_name}"
    mkdir_command = f"mkdir -p {shlex.quote(temp_dir)}"
    cleanup_command = f"rm -rf {shlex.quote(temp_dir)}"

    try:
        run_ssh_command(host, mkdir_command)
        write_remote_file(host, temp_path, content)
        command = _compose_command(temp_dir, ["-f", temp_name, "config"])
        result = run_ssh_command(host, command, timeout=120)
        output = "\n".join([result.stdout, result.stderr]).strip()
        return result.exit_code == 0, output
    finally:
        try:
            run_ssh_command(host, cleanup_command)
        except SSHError:
            pass


def create_project(host: HostConfig, project: str, content: str) -> str:
    project_dir = _project_dir(host, project)
    project_q = shlex.quote(project_dir)
    compose_path = f"{project_dir}/docker-compose.yml"
    mkdir_command = (
        f"if [ -e {project_q} ]; then echo 'Project exists'; exit 1; fi; "
        f"mkdir -p {project_q}"
    )
    result = run_ssh_command(host, mkdir_command)
    if result.exit_code != 0:
        message = result.stderr or result.stdout or "Unable to create project directory"
        raise ComposeError(message)
    try:
        write_remote_file(host, compose_path, content)
    except SSHError as exc:
        try:
            run_ssh_command(host, f"rm -rf {project_q}")
        except SSHError:
            pass
        raise ComposeError(str(exc)) from exc
    return compose_path


def delete_project(host: HostConfig, project: str) -> None:
    project_dir = _project_dir(host, project)
    project_q = shlex.quote(project_dir)
    command = (
        f"if [ ! -d {project_q} ]; then echo 'Project missing'; exit 1; fi; "
        f"rm -rf {project_q}"
    )
    result = run_ssh_command(host, command)
    if result.exit_code != 0:
        message = result.stderr or result.stdout or "Unable to delete project directory"
        raise ComposeError(message)


def logs_command(
    host: HostConfig,
    project: str,
    tail: int = 200,
    service: Optional[str] = None,
    follow: bool = False,
) -> str:
    args = ["logs", "--no-color", "--tail", str(tail)]
    if follow:
        args.append("-f")
    if service:
        args.append(service)
    return _compose_command(_project_dir(host, project), args)


def project_logs(
    host: HostConfig, project: str, tail: int = 200, service: Optional[str] = None
) -> str:
    command = logs_command(host, project, tail=tail, service=service, follow=False)
    result = run_ssh_command(host, command)
    if result.exit_code != 0:
        message = result.stderr or result.stdout or "Unknown error"
        raise ComposeError(message)
    return result.stdout


def start_project(host: HostConfig, project: str) -> SSHResult:
    return _run_compose(host, project, ["up", "-d"])


def start_project_cancelable(host: HostConfig, project: str, stop_event) -> SSHResult:
    return _run_compose_cancelable(host, project, ["up", "-d"], stop_event)


def stop_project(host: HostConfig, project: str) -> SSHResult:
    return _run_compose(host, project, ["stop"])


def stop_project_cancelable(host: HostConfig, project: str, stop_event) -> SSHResult:
    return _run_compose_cancelable(host, project, ["stop"], stop_event)


def restart_project(host: HostConfig, project: str) -> SSHResult:
    return _run_compose(host, project, ["restart"])


def restart_project_cancelable(host: HostConfig, project: str, stop_event) -> SSHResult:
    return _run_compose_cancelable(host, project, ["restart"], stop_event)


def start_service(host: HostConfig, project: str, service: str) -> SSHResult:
    return _run_compose(host, project, ["start", service])


def start_service_cancelable(host: HostConfig, project: str, service: str, stop_event) -> SSHResult:
    return _run_compose_cancelable(host, project, ["start", service], stop_event)


def stop_service(host: HostConfig, project: str, service: str) -> SSHResult:
    return _run_compose(host, project, ["stop", service])


def stop_service_cancelable(host: HostConfig, project: str, service: str, stop_event) -> SSHResult:
    return _run_compose_cancelable(host, project, ["stop", service], stop_event)


def restart_service(host: HostConfig, project: str, service: str) -> SSHResult:
    return _run_compose(host, project, ["restart", service])


def restart_service_cancelable(
    host: HostConfig, project: str, service: str, stop_event
) -> SSHResult:
    return _run_compose_cancelable(host, project, ["restart", service], stop_event)


def run_service_action_cancelable(
    host: HostConfig, project: str, service: str, action: str, stop_event
) -> SSHResult:
    action = action.lower()
    if action == "start":
        return start_service_cancelable(host, project, service, stop_event)
    if action == "stop":
        return stop_service_cancelable(host, project, service, stop_event)
    if action == "restart":
        return restart_service_cancelable(host, project, service, stop_event)
    raise ComposeError(f"Unsupported service action: {action}")

def backup_project(
    host_id: str, host: HostConfig, project: str, backup: BackupConfig
) -> Tuple[str, str]:
    dest, command = build_backup_command(host_id, host, project, backup)
    result = run_ssh_command(host, command, timeout=600)
    if result.exit_code != 0:
        message = result.stderr or result.stdout or "Backup failed"
        raise ComposeError(message)
    output = result.stdout or result.stderr or ""
    return dest, output.strip()


def build_backup_command(
    host_id: str, host: HostConfig, project: str, backup: BackupConfig
) -> Tuple[str, str]:
    project_dir = _project_dir(host, project)
    dest_base = backup.base_path.rstrip("/")
    dest = f"{dest_base}/{project}"

    password_q = shlex.quote(backup.password)
    src_q = shlex.quote(f"{project_dir}/")
    protocol = (backup.protocol or "ssh").lower()

    if protocol == "rsync":
        user_prefix = f"{backup.user}@" if backup.user else ""
        dest_url = f"rsync://{user_prefix}{backup.host}/{dest.lstrip('/')}"
        dest_q = shlex.quote(dest_url)
        primary_cmd = (
            f"RSYNC_PASSWORD={password_q} rsync -az --links --delete --mkpath {src_q} {dest_q}"
        )
        fallback_cmd = (
            f"RSYNC_PASSWORD={password_q} rsync -az --links --delete {src_q} {dest_q}"
        )
        return dest, f"{primary_cmd} || {fallback_cmd}"

    user_host = f"{backup.user}@{backup.host}"
    user_host_q = shlex.quote(user_host)
    dest_q = shlex.quote(dest)
    ssh_opts = f"ssh -p {backup.port} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    ssh_opts_q = shlex.quote(ssh_opts)
    mkdir_cmd = (
        f"sshpass -p {password_q} {ssh_opts} {user_host_q} "
        f"{shlex.quote(f'mkdir -p {dest}')}"
    )
    rsync_cmd = (
        f"sshpass -p {password_q} rsync -az --links --delete -e {ssh_opts_q} "
        f"{src_q} {shlex.quote(f'{user_host}:{dest}/')}"
    )
    return dest, f"{mkdir_cmd} && {rsync_cmd}"


def _parse_ps_output(output: str) -> List[dict]:
    text = output.strip()
    if not text:
        return []
    if text.startswith("["):
        try:
            data = json.loads(text)
            return data if isinstance(data, list) else []
        except json.JSONDecodeError:
            pass
    items = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return items


def _detect_updates(output: str) -> bool:
    lowered = output.lower()
    if not lowered.strip():
        return False
    if "up to date" in lowered or "up-to-date" in lowered or "skipped" in lowered:
        return False
    if "newer image" in lowered or "pull complete" in lowered or "download" in lowered:
        return True
    if "pulling" in lowered:
        return True
    return False


def project_status(host: HostConfig, project: str) -> Tuple[str, List[dict], List[str]]:
    result = _run_compose(host, project, ["ps", "--all", "--format", "json"])
    if not result.stdout.strip():
        return "down", [], []
    items = _parse_ps_output(result.stdout)
    containers = []
    running_count = 0
    issues = []

    for item in items:
        service = item.get("Service") or None
        name = item.get("Name") or service or "unknown"
        state = (item.get("State") or "").lower()
        status = item.get("Status") or ""
        exit_code = item.get("ExitCode")
        containers.append(
            {
                "name": name,
                "service": service,
                "state": state,
                "status": status,
                "exit_code": exit_code,
            }
        )
        is_running = state == "running" or status.lower().startswith("up")
        if is_running:
            running_count += 1
        if exit_code not in (None, 0) or state in ("exited", "dead"):
            issues.append(f"{name} state={state} exit={exit_code}")

    if not containers:
        overall = "down"
    elif running_count == len(containers):
        overall = "up"
    elif running_count == 0:
        overall = "down"
    else:
        overall = "degraded"

    return overall, containers, issues


def _compose_config_json(host: HostConfig, project: str) -> dict:
    result = _run_compose(host, project, ["config", "--format", "json"])
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ComposeError("Compose config JSON parse failed") from exc


def _compose_config_text(host: HostConfig, project: str) -> str:
    result = _run_compose(host, project, ["config"])
    return result.stdout


def _extract_images_from_config(config: object) -> List[str]:
    images: List[str] = []
    if isinstance(config, dict):
        services = config.get("services", {})
        if isinstance(services, dict):
            for service in services.values():
                if isinstance(service, dict):
                    image = service.get("image")
                    if image:
                        images.append(image)
        elif isinstance(services, list):
            for service in services:
                if isinstance(service, dict):
                    image = service.get("image")
                    if image:
                        images.append(image)
    elif isinstance(config, list):
        for item in config:
            images.extend(_extract_images_from_config(item))
    return images


def list_service_images(host: HostConfig, project: str) -> Dict[str, str]:
    service_images: Dict[str, str] = {}
    try:
        config = _compose_config_json(host, project)
        if isinstance(config, dict):
            services = config.get("services", {})
            if isinstance(services, dict):
                for name, service in services.items():
                    if isinstance(service, dict):
                        image = service.get("image")
                        if image:
                            service_images[name] = image
            elif isinstance(services, list):
                for service in services:
                    if isinstance(service, dict):
                        name = service.get("name") or service.get("service")
                        image = service.get("image")
                        if name and image:
                            service_images[name] = image
    except ComposeError:
        pass
    return service_images


def list_project_images(host: HostConfig, project: str) -> List[str]:
    images: List[str] = []
    service_images = list_service_images(host, project)
    if service_images:
        images = list(service_images.values())
    else:
        try:
            config = _compose_config_json(host, project)
            images = _extract_images_from_config(config)
        except ComposeError:
            config_text = _compose_config_text(host, project)
            for line in config_text.splitlines():
                stripped = line.strip()
                if stripped.startswith("image:"):
                    image = stripped.split("image:", 1)[1].strip()
                    if image:
                        images.append(image)

    unique = []
    for image in images:
        if image not in unique:
            unique.append(image)
    return unique


def _local_repo_digests(host: HostConfig, image: str) -> Tuple[List[str], str]:
    image_q = shlex.quote(image)
    command = f"docker image inspect --format '{{{{json .RepoDigests}}}}' {image_q}"
    result = run_ssh_command(host, command)
    if result.exit_code != 0:
        message = result.stderr or result.stdout or "Image not found"
        return [], message
    try:
        digests = json.loads(result.stdout) if result.stdout else []
        return digests or [], ""
    except json.JSONDecodeError:
        return [], "Failed to parse local image digests"


def _local_image_platform(host: HostConfig, image: str) -> Dict[str, Optional[str]]:
    image_q = shlex.quote(image)
    command = (
        "docker image inspect --format "
        "'{{json .Architecture}}|{{json .Os}}|{{json .Variant}}' "
        f"{image_q}"
    )
    result = run_ssh_command(host, command)
    if result.exit_code != 0:
        return {}
    parts = (result.stdout or "").split("|")
    if len(parts) < 2:
        return {}
    try:
        architecture = json.loads(parts[0])
        os_name = json.loads(parts[1])
        variant = json.loads(parts[2]) if len(parts) > 2 and parts[2] else None
    except json.JSONDecodeError:
        return {}
    return {"architecture": architecture, "os": os_name, "variant": variant}


def _remote_manifest(host: HostConfig, image: str) -> dict:
    image_q = shlex.quote(image)
    command = f"docker manifest inspect --verbose {image_q}"
    result = run_ssh_command(host, command)
    if result.exit_code != 0:
        message = result.stderr or result.stdout or "Manifest inspect failed"
        raise ComposeError(message)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ComposeError("Manifest JSON parse failed") from exc


def _select_manifest_digest(
    manifest: object, platform: Dict[str, Optional[str]]
) -> Optional[str]:
    if isinstance(manifest, list):
        for entry in manifest:
            digest = _select_manifest_digest(entry, platform)
            if digest:
                return digest
        return None
    if not isinstance(manifest, dict):
        return None

    manifests = manifest.get("manifests")
    if isinstance(manifests, list) and manifests:
        if platform:
            for entry in manifests:
                entry_platform = entry.get("platform") or entry.get("Platform") or {}
                if (
                    entry_platform.get("architecture") == platform.get("architecture")
                    and entry_platform.get("os") == platform.get("os")
                ):
                    entry_variant = entry_platform.get("variant")
                    if platform.get("variant") and entry_variant:
                        if entry_variant != platform.get("variant"):
                            continue
                    return entry.get("digest") or entry.get("Descriptor", {}).get("digest")
        entry = manifests[0]
        return entry.get("digest") or entry.get("Descriptor", {}).get("digest")
    descriptor = manifest.get("Descriptor") or {}
    return descriptor.get("digest")


def _digest_list(repo_digests: List[str]) -> List[str]:
    digests = []
    for item in repo_digests:
        if "@" in item:
            digests.append(item.split("@", 1)[1])
        else:
            digests.append(item)
    return digests


def check_updates(host: HostConfig, project: str) -> Tuple[bool, bool, str, Dict[str, str]]:
    if not UPDATE_CHECKS_ENABLED:
        return False, False, "Update checks are disabled.", {}
    service_images = list_service_images(host, project)
    images = list_project_images(host, project)
    if not images:
        return False, False, "No images found in compose config.", {}

    results = []
    errors = []
    updates_available = False
    per_service: Dict[str, str] = {}

    image_status: Dict[str, dict] = {}
    for image in images:
        local_digests, local_error = _local_repo_digests(host, image)
        local_platform = _local_image_platform(host, image)
        try:
            manifest = _remote_manifest(host, image)
        except ComposeError as exc:
            image_status[image] = {"status": "unknown", "error": str(exc)}
            errors.append(f"{image}: {exc}")
            continue
        remote_digest = _select_manifest_digest(manifest, local_platform)
        if not remote_digest:
            image_status[image] = {"status": "unknown", "error": "no remote digest"}
            errors.append(f"{image}: unable to determine registry digest")
            continue

        local_digest_list = _digest_list(local_digests)
        if local_digest_list:
            if remote_digest in local_digest_list:
                status = "up-to-date"
            else:
                status = "update-available"
                updates_available = True
        else:
            status = "missing-local-image"
            updates_available = True
            if local_error:
                errors.append(f"{image}: local image check failed ({local_error})")

        image_status[image] = {
            "status": status,
            "local": local_digest_list[0] if local_digest_list else "none",
            "remote": remote_digest,
        }
        results.append(
            f"{image}: local={image_status[image]['local']} remote={remote_digest} status={status}"
        )

    if service_images:
        for service_name, image in service_images.items():
            status = image_status.get(image, {}).get("status", "unknown")
            if status in ("update-available", "missing-local-image"):
                per_service[service_name] = "yes"
            elif status == "up-to-date":
                per_service[service_name] = "no"
            else:
                per_service[service_name] = "unknown"
            results.append(f"{service_name}: image={image} status={status}")

    supported = bool(images)
    details_lines = results + errors
    details = "\n".join(details_lines).strip()
    return supported, updates_available, details, per_service


def check_image_update(host: HostConfig, image: str) -> Optional[bool]:
    if not UPDATE_CHECKS_ENABLED:
        return None
    local_digests, local_error = _local_repo_digests(host, image)
    local_platform = _local_image_platform(host, image)
    try:
        manifest = _remote_manifest(host, image)
    except ComposeError:
        return None
    remote_digest = _select_manifest_digest(manifest, local_platform)
    if not remote_digest:
        return None
    local_digest_list = _digest_list(local_digests)
    if local_digest_list:
        return remote_digest not in local_digest_list
    if local_error:
        return True
    return True


def apply_updates(host: HostConfig, project: str) -> Tuple[bool, str]:
    overall, _, _ = project_status(host, project)
    was_running = overall in ("up", "degraded")
    pull_result = _run_compose(host, project, ["pull"])
    pull_output = "\n".join([pull_result.stdout, pull_result.stderr]).strip()
    updates_applied = _detect_updates(pull_output)
    outputs = [pull_output]
    if was_running:
        up_result = _run_compose(host, project, ["up", "-d"])
        outputs.extend([up_result.stdout, up_result.stderr])
    combined_output = "\n".join(outputs).strip()
    return updates_applied, combined_output


def apply_updates_cancelable(host: HostConfig, project: str, stop_event) -> Tuple[bool, str]:
    overall, _, _ = project_status(host, project)
    was_running = overall in ("up", "degraded")
    pull_result = _run_compose_cancelable(host, project, ["pull"], stop_event, timeout=300)
    pull_output = "\n".join([pull_result.stdout, pull_result.stderr]).strip()
    updates_applied = _detect_updates(pull_output)
    if stop_event.is_set():
        raise ComposeCancelled("Update cancelled")
    outputs = [pull_output]
    if was_running:
        up_result = _run_compose_cancelable(
            host, project, ["up", "-d"], stop_event, timeout=300
        )
        outputs.extend([up_result.stdout, up_result.stderr])
    combined_output = "\n".join(outputs).strip()
    return updates_applied, combined_output


def run_project_action_cancelable(
    host: HostConfig, project: str, action: str, stop_event
) -> Tuple[Optional[bool], str]:
    action = action.lower()
    if action == "start":
        result = start_project_cancelable(host, project, stop_event)
        return None, result.stdout
    if action == "stop":
        result = stop_project_cancelable(host, project, stop_event)
        return None, result.stdout
    if action == "restart":
        result = restart_project_cancelable(host, project, stop_event)
        return None, result.stdout
    if action == "update":
        updates_applied, output = apply_updates_cancelable(host, project, stop_event)
        return updates_applied, output
    raise ComposeError(f"Unsupported action: {action}")
