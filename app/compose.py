import contextlib
import json
import logging
import os
import queue
import re
import shlex
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, Iterator, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from .config import BackupConfig, HostConfig
from .docker_context import context_name, docker_env
from .ssh import (
    SSHError,
    SSHResult,
    read_remote_file,
    run_ssh_command,
    run_ssh_command_password,
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
UPDATE_CHECKS_ENABLED = os.getenv("UPDATE_CHECKS_ENABLED", "true").lower() in (
    "1",
    "true",
    "yes",
    "on",
)
_SAFE_KEY_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_REGISTRY_AUTH_PARAM_RE = re.compile(r'(\w+)="([^"]*)"')
_API_TOO_NEW_RE = re.compile(r"Maximum supported API version is ([0-9.]+)")
logger = logging.getLogger("rpm")

def _redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    return {
        key: ("<redacted>" if key.lower() == "authorization" else value)
        for key, value in headers.items()
    }

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
            value, consumed = _consume_value(tokens, index, "--privileged")
            if consumed:
                privileged = value.strip().lower() in ("1", "true", "yes", "on")
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

def _require_host_id(host: HostConfig) -> str:
    host_id = getattr(host, "host_id", None)
    if not host_id:
        raise ComposeError("Host id is required for docker context")
    return host_id

def _docker_context(host: HostConfig) -> str:
    return context_name(_require_host_id(host))

def _extract_api_version(message: str) -> Optional[str]:
    if not message:
        return None
    match = _API_TOO_NEW_RE.search(message)
    if match:
        return match.group(1)
    return None

def _docker_env(host: HostConfig) -> Dict[str, str]:
    host_id = _require_host_id(host)
    return docker_env(host_id, host)

def _terminate_process(process: subprocess.Popen) -> None:
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()

def _run_docker_with_env(
    host: HostConfig,
    args: List[str],
    env: Dict[str, str],
    timeout: int,
) -> SSHResult:
    command = ["docker", "--context", _docker_context(host)] + args
    command_str = " ".join(shlex.quote(arg) for arg in command)
    logger.debug(
        "Docker exec host_id=%s command=%s",
        getattr(host, "host_id", None),
        command_str,
    )
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ComposeError("docker CLI not available") from exc
    return SSHResult(
        command=command_str,
        exit_code=result.returncode,
        stdout=(result.stdout or "").strip(),
        stderr=(result.stderr or "").strip(),
    )

def _run_docker(host: HostConfig, args: List[str], timeout: int = 120) -> SSHResult:
    env = _docker_env(host)
    result = _run_docker_with_env(host, args, env, timeout)
    if result.exit_code != 0:
        max_version = _extract_api_version(result.stderr)
        if not max_version:
            max_version = _extract_api_version(result.stdout)
        if max_version:
            logger.debug(
                "Docker API fallback host_id=%s api_version=%s",
                getattr(host, "host_id", None),
                max_version,
            )
            env_retry = env.copy()
            env_retry["DOCKER_API_VERSION"] = max_version
            result = _run_docker_with_env(host, args, env_retry, timeout)
    return result

def _run_docker_cancelable(
    host: HostConfig, args: List[str], stop_event, timeout: int = 120
) -> SSHResult:
    if stop_event.is_set():
        raise ComposeCancelled("Compose action cancelled")
    env = _docker_env(host)
    command = ["docker", "--context", _docker_context(host)] + args
    command_str = " ".join(shlex.quote(arg) for arg in command)
    logger.debug(
        "Docker exec host_id=%s command=%s",
        getattr(host, "host_id", None),
        command_str,
    )
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            bufsize=1,
        )
    except FileNotFoundError as exc:
        raise ComposeError("docker CLI not available") from exc
    stdout_lines: List[str] = []
    stderr_lines: List[str] = []
    output_queue: queue.Queue[tuple[str, Optional[str]]] = queue.Queue()
    def reader(stream, name: str) -> None:
        for line in iter(stream.readline, ""):
            output_queue.put((name, line))
        output_queue.put((name, None))
        stream.close()
    threads = [
        threading.Thread(target=reader, args=(process.stdout, "stdout"), daemon=True),
        threading.Thread(target=reader, args=(process.stderr, "stderr"), daemon=True),
    ]
    for thread in threads:
        thread.start()
    done = 0
    start_time = time.monotonic()
    while done < 2:
        if stop_event.is_set():
            _terminate_process(process)
            raise ComposeCancelled("Compose action cancelled")
        if timeout and time.monotonic() - start_time > timeout:
            _terminate_process(process)
            raise ComposeError("Compose command timed out")
        try:
            name, line = output_queue.get(timeout=0.1)
        except queue.Empty:
            if process.poll() is not None and done >= 2:
                break
            continue
        if line is None:
            done += 1
            continue
        if name == "stdout":
            stdout_lines.append(line)
        else:
            stderr_lines.append(line)
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        _terminate_process(process)
    result = SSHResult(
        command=command_str,
        exit_code=process.returncode or 0,
        stdout="".join(stdout_lines).strip(),
        stderr="".join(stderr_lines).strip(),
    )
    if result.exit_code != 0:
        max_version = _extract_api_version(result.stderr)
        if not max_version:
            max_version = _extract_api_version(result.stdout)
        if max_version:
            if stop_event.is_set():
                raise ComposeCancelled("Compose action cancelled")
            logger.debug(
                "Docker API fallback host_id=%s api_version=%s",
                getattr(host, "host_id", None),
                max_version,
            )
            env_retry = env.copy()
            env_retry["DOCKER_API_VERSION"] = max_version
            return _run_docker_with_env(host, args, env_retry, timeout)
    return result

def _stream_docker_command(
    host: HostConfig,
    args: List[str],
    stop_event,
    timeout: int = 300,
    include_exit: bool = False,
) -> Iterator[Tuple[str, str]]:
    env = _docker_env(host)
    command = ["docker", "--context", _docker_context(host)] + args
    command_str = " ".join(shlex.quote(arg) for arg in command)
    logger.debug(
        "Docker stream host_id=%s command=%s",
        getattr(host, "host_id", None),
        command_str,
    )
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            bufsize=1,
        )
    except FileNotFoundError as exc:
        raise ComposeError("docker CLI not available") from exc
    output_queue: queue.Queue[tuple[str, Optional[str]]] = queue.Queue()
    def reader(stream, name: str) -> None:
        for line in iter(stream.readline, ""):
            output_queue.put((name, line))
        output_queue.put((name, None))
        stream.close()
    threads = [
        threading.Thread(target=reader, args=(process.stdout, "stdout"), daemon=True),
        threading.Thread(target=reader, args=(process.stderr, "stderr"), daemon=True),
    ]
    for thread in threads:
        thread.start()
    done = 0
    start_time = time.monotonic()
    while done < 2:
        if stop_event.is_set():
            _terminate_process(process)
            break
        if timeout and time.monotonic() - start_time > timeout:
            _terminate_process(process)
            break
        try:
            name, line = output_queue.get(timeout=0.1)
        except queue.Empty:
            if process.poll() is not None and done >= 2:
                break
            continue
        if line is None:
            done += 1
            continue
        yield (name, line.rstrip("\n"))
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        _terminate_process(process)
    if include_exit and not stop_event.is_set():
        exit_code = process.returncode
        if exit_code is None:
            try:
                exit_code = process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                exit_code = 0
        yield ("exit", str(exit_code))
@contextlib.contextmanager
def _compose_tempfile(
    host: HostConfig, project: str, content: Optional[str] = None
) -> Iterator[str]:
    if content is None:
        _, content = read_compose_file(host, project)
    fd, path = tempfile.mkstemp(prefix="rpm-compose-", suffix=".yml")
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(content)
        yield path
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass

def _compose_args(project_dir: str, project: str, compose_path: str) -> List[str]:
    return [
        "compose",
        "-f",
        compose_path,
        "--project-name",
        project,
        "--project-directory",
        project_dir,
    ]

def _sanitize_compose_args(args: List[str]) -> List[str]:
    cleaned: List[str] = []
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in ("-f", "--file", "--project-directory", "--project-name", "-p"):
            skip_next = True
            continue
        if arg.startswith("-f") and len(arg) > 2:
            continue
        if arg.startswith(("--file=", "--project-directory=", "--project-name=", "-p=")):
            continue
        cleaned.append(arg)
    return cleaned

def _run_compose_with_content(
    host: HostConfig,
    project_dir: str,
    project_name: str,
    args: List[str],
    content: Optional[str] = None,
    timeout: int = 120,
    stop_event=None,
) -> SSHResult:
    with _compose_tempfile(host, project_name, content) as compose_path:
        compose_args = _compose_args(project_dir, project_name, compose_path) + args
        if stop_event is None:
            result = _run_docker(host, compose_args, timeout=timeout)
        else:
            result = _run_docker_cancelable(host, compose_args, stop_event, timeout=timeout)
    if result.exit_code != 0:
        message = result.stderr or result.stdout or "Unknown error"
        raise ComposeError(message)
    return result

def _run_compose(host: HostConfig, project: str, args: List[str], timeout: int = 120) -> SSHResult:
    return _run_compose_with_content(
        host,
        _project_dir(host, project),
        project,
        args,
        timeout=timeout,
    )

def _run_compose_cancelable(
    host: HostConfig,
    project: str,
    args: List[str],
    stop_event,
    timeout: int = 120,
) -> SSHResult:
    if stop_event.is_set():
        raise ComposeCancelled("Compose action cancelled")
    try:
        return _run_compose_with_content(
            host,
            _project_dir(host, project),
            project,
            args,
            timeout=timeout,
            stop_event=stop_event,
        )
    except ComposeCancelled:
        raise

def _stream_compose_with_content(
    host: HostConfig,
    project_dir: str,
    project_name: str,
    args: List[str],
    stop_event,
    timeout: int = 300,
    include_exit: bool = False,
) -> Iterator[Tuple[str, str]]:
    with _compose_tempfile(host, project_name, None) as compose_path:
        compose_args = _compose_args(project_dir, project_name, compose_path) + args
        yield from _stream_docker_command(
            host,
            compose_args,
            stop_event,
            timeout=timeout,
            include_exit=include_exit,
        )

def stream_project_logs(
    host: HostConfig,
    project: str,
    tail: int,
    service: Optional[str],
    stop_event,
    timeout: int = 300,
) -> Iterator[Tuple[str, str]]:
    args = logs_command(host, project, tail=tail, service=service, follow=True)
    return _stream_compose_with_content(
        host,
        _project_dir(host, project),
        project,
        args,
        stop_event,
        timeout=timeout,
    )

def stream_compose_command(
    host: HostConfig,
    project: str,
    command: str,
    stop_event,
    timeout: int = 300,
) -> Iterator[Tuple[str, str]]:
    args = _sanitize_compose_args(_parse_compose_command(command))
    return _stream_compose_with_content(
        host,
        _project_dir(host, project),
        project,
        args,
        stop_event,
        timeout=timeout,
        include_exit=True,
    )

def _parse_compose_command(command: str) -> List[str]:
    if not command or not command.strip():
        raise ComposeError("Command is required")
    args = shlex.split(command)
    if not args:
        raise ComposeError("Command is required")
    if args[0] == "docker":
        if len(args) < 2 or args[1] != "compose":
            raise ComposeError("Command must be a docker compose command")
        args = args[2:]
    elif args[0] == "docker-compose":
        args = args[1:]
    elif args[0] == "compose":
        args = args[1:]
    if not args:
        raise ComposeError("Compose arguments are required")
    return args

def run_compose_command(
    host: HostConfig, project: str, command: str, timeout: int = 300
) -> SSHResult:
    args = _sanitize_compose_args(_parse_compose_command(command))
    return _run_compose(host, project, args, timeout=timeout)

def compose_command_string(host: HostConfig, project: str, command: str) -> str:
    _ = (host, project)
    args = _sanitize_compose_args(_parse_compose_command(command))
    return "docker compose " + " ".join(shlex.quote(arg) for arg in args)

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


def validate_compose_content(
    host: HostConfig, project: str, content: str
) -> Tuple[bool, str]:
    project_dir = _project_dir(host, project)
    with _compose_tempfile(host, project, content) as compose_path:
        args = _compose_args(project_dir, project, compose_path) + ["config"]
        result = _run_docker(host, args, timeout=120)
    output = "\n".join([result.stdout, result.stderr]).strip()
    return result.exit_code == 0, output


def validate_compose_content_temp(host: HostConfig, content: str) -> Tuple[bool, str]:
    project_dir = host.project_root.rstrip("/") or "/"
    project_name = "temp"
    with _compose_tempfile(host, project_name, content) as compose_path:
        args = _compose_args(project_dir, project_name, compose_path) + ["config"]
        result = _run_docker(host, args, timeout=120)
    output = "\n".join([result.stdout, result.stderr]).strip()
    return result.exit_code == 0, output


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
) -> List[str]:
    _ = (host, project)
    args = ["logs", "--no-color", "--tail", str(tail)]
    if follow:
        args.append("-f")
    if service:
        args.append(service)
    return args

def project_logs(
    host: HostConfig, project: str, tail: int = 200, service: Optional[str] = None
) -> str:
    args = logs_command(host, project, tail=tail, service=service, follow=False)
    result = _run_compose(host, project, args)
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

def hard_restart_project(host: HostConfig, project: str) -> str:
    down_result = _run_compose(host, project, ["down"])
    up_result = _run_compose(host, project, ["up", "-d"])
    outputs = [
        down_result.stdout,
        down_result.stderr,
        up_result.stdout,
        up_result.stderr,
    ]
    return "\n".join(output for output in outputs if output).strip()

def hard_restart_project_cancelable(host: HostConfig, project: str, stop_event) -> str:
    down_result = _run_compose_cancelable(host, project, ["down"], stop_event)
    if stop_event.is_set():
        raise ComposeCancelled("Hard restart cancelled")
    up_result = _run_compose_cancelable(host, project, ["up", "-d"], stop_event)
    outputs = [
        down_result.stdout,
        down_result.stderr,
        up_result.stdout,
        up_result.stderr,
    ]
    return "\n".join(output for output in outputs if output).strip()

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


def hard_restart_service_cancelable(
    host: HostConfig, project: str, service: str, stop_event
) -> SSHResult:
    _run_compose_cancelable(host, project, ["stop", service], stop_event)
    if stop_event.is_set():
        raise ComposeCancelled("Hard restart cancelled")
    return _run_compose_cancelable(host, project, ["up", "-d", service], stop_event)


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
    if action == "hard_restart":
        return hard_restart_service_cancelable(host, project, service, stop_event)
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

def project_exists(host: HostConfig, project: str) -> bool:
    project_dir = _project_dir(host, project)
    command = f"test -d {shlex.quote(project_dir)}"
    result = run_ssh_command(host, command, timeout=30)
    return result.exit_code == 0

def list_backup_projects(backup: BackupConfig) -> List[str]:
    base_path = backup.base_path.rstrip("/") or "/"
    protocol = (backup.protocol or "ssh").lower()
    if protocol == "rsync":
        user_prefix = f"{backup.user}@" if backup.user else ""
        src_path = base_path.lstrip("/")
        if src_path and not src_path.endswith("/"):
            src_path = f"{src_path}/"
        src_url = f"rsync://{user_prefix}{backup.host}/{src_path}"
        env = os.environ.copy()
        env["RSYNC_PASSWORD"] = backup.password
        logger.debug(
            "RSYNC list command: rsync --list-only --out-format=%%n --filter=+ */ --filter=- * %s",
            src_url,
        )
        try:
            result = subprocess.run(
                [
                    "rsync",
                    "--list-only",
                    "--out-format=%n",
                    "--filter=+ */",
                    "--filter=- *",
                    src_url,
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
                check=False,
            )
        except FileNotFoundError as exc:
            raise ComposeError("rsync is not available to list backups") from exc
        if result.returncode != 0:
            message = result.stderr or result.stdout or "Backup listing failed"
            raise ComposeError(message)
        projects = []
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            parts = stripped.split()
            if len(parts) >= 5:
                name = parts[4]
            else:
                name = stripped.rstrip("/")
                name = name.lstrip("./")
                name = name.split("/")[-1]
            name = name.rstrip("/")
            if not name or name in (".", ".."):
                continue
            projects.append(name)
        return projects
    command = f"ls -1 {shlex.quote(base_path)}"
    result = run_ssh_command_password(
        backup.host,
        backup.user,
        backup.password,
        command,
        port=backup.port,
        timeout=30,
    )
    if result.exit_code != 0:
        message = result.stderr or result.stdout or "Backup listing failed"
        raise ComposeError(message)
    projects = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return projects

def restore_project(
    host_id: str, host: HostConfig, project: str, backup: BackupConfig
) -> Tuple[str, str]:
    dest, command = build_restore_command(host_id, host, project, backup)
    result = run_ssh_command(host, command, timeout=600)
    if result.exit_code != 0:
        message = result.stderr or result.stdout or "Restore failed"
        raise ComposeError(message)
    output = result.stdout or result.stderr or ""
    return dest, output.strip()

def build_restore_command(
    host_id: str, host: HostConfig, project: str, backup: BackupConfig
) -> Tuple[str, str]:
    project_dir = _project_dir(host, project)
    project_root = host.project_root.rstrip("/")
    if not project_root:
        raise ComposeError("Project root is not configured for restore.")
    dest_dir = f"{project_root}/"
    dest_q = shlex.quote(dest_dir)
    src_base = backup.base_path.rstrip("/")
    src = f"{src_base}/{project}"
    password_q = shlex.quote(backup.password)
    protocol = (backup.protocol or "ssh").lower()
    mkdir_cmd = f"mkdir -p {shlex.quote(project_root)}"
    if protocol == "rsync":
        user_prefix = f"{backup.user}@" if backup.user else ""
        src_url = f"rsync://{user_prefix}{backup.host}/{src.lstrip('/')}"
        src_q = shlex.quote(src_url)
        rsync_cmd = (
            f"RSYNC_PASSWORD={password_q} rsync -az --links --delete {src_q} {dest_q}"
        )
        logger.debug("Restore rsync src=%s dest=%s", src_url, dest_dir)
        return project_dir, f"{mkdir_cmd} && {rsync_cmd}"
    user_host = f"{backup.user}@{backup.host}"
    user_host_q = shlex.quote(user_host)
    ssh_opts = f"ssh -p {backup.port} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    ssh_opts_q = shlex.quote(ssh_opts)
    src_q = shlex.quote(f"{user_host}:{src}")
    rsync_cmd = (
        f"sshpass -p {password_q} rsync -az --links --delete -e {ssh_opts_q} {src_q} {dest_q}"
    )
    logger.debug("Restore rsync src=%s dest=%s", f"{user_host}:{src}", dest_dir)
    return project_dir, f"{mkdir_cmd} && {rsync_cmd}"

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

def _parse_label_map(value: str) -> Dict[str, str]:
    labels: Dict[str, str] = {}
    if not value:
        return labels
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        key, sep, val = part.partition("=")
        if not sep:
            continue
        labels[key] = val
    return labels


def _docker_ps(host: HostConfig, project: str) -> List[dict]:
    result = _run_docker(
        host,
        [
            "ps",
            "-a",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--format",
            "{{json .}}",
        ],
        timeout=60,
    )
    if result.exit_code != 0:
        message = result.stderr or result.stdout or "Docker ps failed"
        raise ComposeError(message)
    items = _parse_ps_output(result.stdout)
    enriched: List[dict] = []
    for item in items:
        labels = _parse_label_map(item.get("Labels") or "")
        service = labels.get("com.docker.compose.service")
        name = item.get("Names") or item.get("Name") or service or "unknown"
        status = item.get("Status") or ""
        state = (item.get("State") or "").lower()
        if not state:
            lowered = status.lower()
            if lowered.startswith("up"):
                state = "running"
            elif lowered.startswith("exited"):
                state = "exited"
            elif lowered.startswith("created"):
                state = "created"
            elif lowered.startswith("paused"):
                state = "paused"
            else:
                state = "unknown"
        enriched.append(
            {
                "ID": item.get("ID"),
                "Name": name,
                "Service": service or name,
                "State": state,
                "Status": status,
            }
        )
    names = [item["Name"] for item in enriched if item.get("Name")]
    if names:
        inspect_result = _run_docker(
            host,
            ["inspect", "--format", "{{json .}}"] + names,
            timeout=60,
        )
        if inspect_result.exit_code == 0:
            inspect_map: Dict[str, dict] = {}
            for entry in _parse_stats_output(inspect_result.stdout):
                name = (entry.get("Name") or "").lstrip("/")
                if name:
                    inspect_map[name] = entry
            for item in enriched:
                entry = inspect_map.get(item.get("Name"))
                if not entry:
                    continue
                state = entry.get("State") or {}
                status = state.get("Status")
                if status:
                    item["State"] = status
                if "ExitCode" in state:
                    item["ExitCode"] = state.get("ExitCode")
    return enriched


def _parse_stats_output(output: str) -> List[dict]:
    text = output.strip()
    if not text:
        return []
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

def _parse_docker_timestamp(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    raw = value.strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    if "." in raw:
        base, rest = raw.split(".", 1)
        tz_part = ""
        frac = rest
        for sign in ("+", "-"):
            idx = rest.rfind(sign)
            if idx > 0:
                frac = rest[:idx]
                tz_part = rest[idx:]
                break
        frac = (frac[:6]).ljust(6, "0")
        raw = f"{base}.{frac}{tz_part}"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)

def _parse_int(value: object) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None

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

def service_container(host: HostConfig, project: str, service: str) -> str:
    items = _docker_ps(host, project)
    if not items:
        raise ComposeError("No containers found")
    service_key = service.lower()
    matches = [
        item for item in items
        if (item.get("Service") or "").lower() == service_key
    ]
    if not matches:
        raise ComposeError(f"Service not found: {service}")
    def is_running(item: dict) -> bool:
        state = (item.get("State") or "").lower()
        status = (item.get("Status") or "").lower()
        return state == "running" or status.startswith("up")
    selected = next((item for item in matches if is_running(item)), matches[0])
    name = selected.get("Name") or selected.get("Service")
    if not name:
        raise ComposeError("Service container name unavailable")
    return name

def project_status(host: HostConfig, project: str) -> Tuple[str, List[dict], List[str]]:
    items = _docker_ps(host, project)
    if not items:
        return "down", [], []
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

def project_stats(host: HostConfig, project: str) -> List[dict]:
    items = _docker_ps(host, project)
    if not items:
        return []
    entries = []
    names = []
    for item in items:
        name = item.get("Name") or item.get("Service") or "unknown"
        service = item.get("Service") or name
        container_id = item.get("ID")
        names.append(name)
        entries.append({"name": name, "service": service, "id": container_id})
    stats_map: Dict[str, dict] = {}
    if names:
        stats_result = _run_docker(
            host, ["stats", "--no-stream", "--format", "{{json .}}"], timeout=60
        )
        if stats_result.exit_code == 0:
            target_names = set(names)
            for entry in _parse_stats_output(stats_result.stdout):
                name = entry.get("Name")
                if name and name in target_names:
                    stats_map[name] = entry
        else:
            logger.debug(
                "Docker stats failed host=%s project=%s error=%s",
                host.host,
                project,
                stats_result.stderr or stats_result.stdout,
            )
    inspect_map: Dict[str, dict] = {}
    if names:
        inspect_args = ["inspect", "--format", "{{json .}}"] + names
        inspect_result = _run_docker(host, inspect_args, timeout=60)
        if inspect_result.exit_code == 0:
            for entry in _parse_stats_output(inspect_result.stdout):
                name = (entry.get("Name") or "").lstrip("/")
                if name:
                    inspect_map[name] = entry
        else:
            logger.debug(
                "Docker inspect failed host=%s project=%s error=%s",
                host.host,
                project,
                inspect_result.stderr or inspect_result.stdout,
            )
    now = datetime.now(timezone.utc)
    results = []
    for entry in entries:
        name = entry["name"]
        stats = stats_map.get(name, {})
        inspect = inspect_map.get(name, {})
        state = inspect.get("State") or {}
        started_at = _parse_docker_timestamp(state.get("StartedAt"))
        uptime_seconds = None
        if started_at:
            uptime_seconds = max(0, int((now - started_at).total_seconds()))
        results.append(
            {
                "service": entry["service"],
                "name": name,
                "cpu_percent": stats.get("CPUPerc"),
                "mem_usage": stats.get("MemUsage"),
                "mem_percent": stats.get("MemPerc"),
                "net_io": stats.get("NetIO"),
                "block_io": stats.get("BlockIO"),
                "pids": _parse_int(stats.get("PIDs")),
                "uptime_seconds": uptime_seconds,
                "restarts": _parse_int(inspect.get("RestartCount")),
            }
        )
    return results

def project_ports(host: HostConfig, project: str) -> List[dict]:
    items = _docker_ps(host, project)
    if not items:
        return []
    name_to_service: Dict[str, str] = {}
    names: List[str] = []
    for item in items:
        name = item.get("Name") or item.get("Service") or "unknown"
        service = item.get("Service") or name
        name_to_service[name] = service
        names.append(name)
    if not names:
        return []
    inspect_args = ["inspect", "--format", "{{json .}}"] + names
    inspect_result = _run_docker(host, inspect_args, timeout=60)
    if inspect_result.exit_code != 0:
        message = inspect_result.stderr or inspect_result.stdout or "Docker inspect failed"
        raise ComposeError(message)
    ports: List[dict] = []
    for entry in _parse_stats_output(inspect_result.stdout):
        name = (entry.get("Name") or "").lstrip("/")
        service = name_to_service.get(name, name or "unknown")
        settings = entry.get("NetworkSettings") or {}
        port_map = settings.get("Ports") or {}
        if not isinstance(port_map, dict):
            continue
        for key, bindings in port_map.items():
            if not key:
                continue
            if "/" in key:
                container_port, protocol = key.split("/", 1)
            else:
                container_port, protocol = key, None
            if not bindings:
                continue
            for binding in bindings:
                host_ip = None
                host_port = None
                if isinstance(binding, dict):
                    host_ip = binding.get("HostIp")
                    host_port = binding.get("HostPort")
                ports.append(
                    {
                        "service": service,
                        "name": name or service,
                        "container_port": container_port,
                        "protocol": protocol,
                        "host_ip": host_ip,
                        "host_port": host_port,
                    }
                )
    return ports

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
    result = _run_docker(
        host, ["image", "inspect", "--format", "{{json .RepoDigests}}", image]
    )
    if result.exit_code != 0:
        message = result.stderr or result.stdout or "Image not found"
        return [], message
    try:
        digests = json.loads(result.stdout) if result.stdout else []
        return digests or [], ""
    except json.JSONDecodeError:
        return [], "Failed to parse local image digests"

def _local_image_platform(host: HostConfig, image: str) -> Dict[str, Optional[str]]:
    result = _run_docker(
        host,
        [
            "image",
            "inspect",
            "--format",
            "{{json .Architecture}}|{{json .Os}}|{{json .Variant}}",
            image,
        ],
    )
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

def _parse_image_reference(image: str) -> Tuple[str, str, str, bool]:
    name = image
    reference = "latest"
    is_digest = False
    if "@" in image:
        name, reference = image.split("@", 1)
        is_digest = True
    else:
        last_segment = name.rsplit("/", 1)[-1]
        if ":" in last_segment:
            name, reference = name.rsplit(":", 1)
    if not name:
        raise ComposeError("Invalid image reference")
    first_segment = name.split("/", 1)[0]
    if "." in first_segment or ":" in first_segment or first_segment == "localhost":
        registry = first_segment
        repository = name.split("/", 1)[1] if "/" in name else ""
    else:
        registry = "registry-1.docker.io"
        repository = name
    if registry in ("docker.io", "index.docker.io"):
        registry = "registry-1.docker.io"
    if registry == "registry-1.docker.io" and "/" not in repository:
        repository = f"library/{repository}"
    if not repository:
        raise ComposeError("Invalid image reference")
    return registry, repository, reference, is_digest

def _parse_www_authenticate(value: Optional[str]) -> Dict[str, str]:
    if not value:
        return {}
    if not value.lower().startswith("bearer "):
        return {}
    params = dict(_REGISTRY_AUTH_PARAM_RE.findall(value))
    return params

def _fetch_registry_token(auth: Dict[str, str]) -> str:
    realm = auth.get("realm")
    if not realm:
        raise ComposeError("Registry auth missing realm")
    params = {}
    service = auth.get("service")
    scope = auth.get("scope")
    if service:
        params["service"] = service
    if scope:
        params["scope"] = scope
    url = realm
    if params:
        url = f"{realm}?{urlencode(params)}"
    request = Request(url, headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=15) as response:
            payload = response.read()
    except (HTTPError, URLError) as exc:
        raise ComposeError(f"Registry auth failed: {exc}") from exc
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ComposeError("Registry auth response parse failed") from exc
    token = data.get("token") or data.get("access_token")
    if not token:
        raise ComposeError("Registry auth token missing")
    return token

def _registry_request_json(url: str, headers: Dict[str, str]) -> Tuple[dict, Dict[str, str]]:
    request = Request(url, headers=headers)
    try:
        logger.debug(
            "Registry request url=%s headers=%s", url, _redact_headers(headers)
        )
        with urlopen(request, timeout=15) as response:
            payload = response.read()
            response_headers = dict(response.headers)
            logger.debug(
                "Registry response url=%s status=%s headers=%s",
                url,
                response.getcode(),
                _redact_headers(response_headers),
            )
            return json.loads(payload), response_headers
    except HTTPError as exc:
        if exc.code == 401:
            logger.debug(
                "Registry response url=%s status=401 auth=%s",
                url,
                exc.headers.get("WWW-Authenticate"),
            )
            auth = _parse_www_authenticate(exc.headers.get("WWW-Authenticate"))
            if not auth:
                raise ComposeError("Registry authentication required") from exc
            token = _fetch_registry_token(auth)
            retry_headers = dict(headers)
            retry_headers["Authorization"] = f"Bearer {token}"
            retry_request = Request(url, headers=retry_headers)
            try:
                logger.debug(
                    "Registry retry url=%s headers=%s",
                    url,
                    _redact_headers(retry_headers),
                )
                with urlopen(retry_request, timeout=15) as response:
                    payload = response.read()
                    response_headers = dict(response.headers)
                    logger.debug(
                        "Registry response url=%s status=%s headers=%s",
                        url,
                        response.getcode(),
                        _redact_headers(response_headers),
                    )
                    return json.loads(payload), response_headers
            except (HTTPError, URLError) as retry_exc:
                raise ComposeError(f"Registry request failed: {retry_exc}") from retry_exc
            except json.JSONDecodeError as retry_exc:
                raise ComposeError("Registry manifest parse failed") from retry_exc
        raise ComposeError(f"Registry request failed: {exc}") from exc
    except URLError as exc:
        raise ComposeError(f"Registry request failed: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ComposeError("Registry manifest parse failed") from exc

def _remote_manifest(host: HostConfig, image: str) -> dict:
    _ = host
    registry, repository, reference, is_digest = _parse_image_reference(image)
    if is_digest:
        return {"Descriptor": {"digest": reference}}
    url = f"https://{registry}/v2/{repository}/manifests/{reference}"
    headers = {
        "Accept": (
            "application/vnd.oci.image.index.v1+json, "
            "application/vnd.docker.distribution.manifest.list.v2+json, "
            "application/vnd.oci.image.manifest.v1+json, "
            "application/vnd.docker.distribution.manifest.v2+json, "
            "application/vnd.docker.distribution.manifest.v1+json"
        )
    }
    manifest, response_headers = _registry_request_json(url, headers)
    digest = None
    for key, value in response_headers.items():
        if key.lower() == "docker-content-digest":
            digest = value
            break
    if digest and isinstance(manifest, dict):
        manifest.setdefault("Descriptor", {})["digest"] = digest
    return manifest

def _select_manifest_digest(
    manifest: object,
    platform: Dict[str, Optional[str]],
    local_digests: Optional[List[str]] = None,
) -> Optional[str]:
    if isinstance(manifest, list):
        for entry in manifest:
            digest = _select_manifest_digest(entry, platform, local_digests)
            if digest:
                return digest
        return None
    if not isinstance(manifest, dict):
        return None
    local_digest_set = set(_digest_list(local_digests or []))
    descriptor = manifest.get("Descriptor") or {}
    descriptor_digest = descriptor.get("digest")
    if descriptor_digest and descriptor_digest in local_digest_set:
        logger.debug("Manifest digest selected via descriptor match: %s", descriptor_digest)
        return descriptor_digest
    manifests = manifest.get("manifests")
    if isinstance(manifests, list) and manifests:
        if local_digest_set:
            for entry in manifests:
                digest = entry.get("digest") or entry.get("Descriptor", {}).get("digest")
                if digest in local_digest_set:
                    logger.debug("Manifest digest selected via local match: %s", digest)
                    return digest
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
                    digest = entry.get("digest") or entry.get("Descriptor", {}).get("digest")
                    if digest:
                        logger.debug("Manifest digest selected via platform match: %s", digest)
                    return digest
        entry = manifests[0]
        digest = entry.get("digest") or entry.get("Descriptor", {}).get("digest")
        if digest:
            logger.debug("Manifest digest selected via manifest fallback: %s", digest)
        return digest
    return descriptor_digest

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
        remote_digest = _select_manifest_digest(manifest, local_platform, local_digests)
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
    remote_digest = _select_manifest_digest(manifest, local_platform, local_digests)
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
    if action == "hard_restart":
        output = hard_restart_project_cancelable(host, project, stop_event)
        return None, output
    if action == "update":
        updates_applied, output = apply_updates_cancelable(host, project, stop_event)
        return updates_applied, output
    raise ComposeError(f"Unsupported action: {action}")
