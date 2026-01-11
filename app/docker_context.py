import logging
import os
import shlex
from pathlib import Path
import subprocess
from typing import Dict
from .config import ConfigError, HostConfig
from .paths import (
    config_path,
    delete_host_key,
    ensure_config_dirs,
    host_key_path,
    write_host_key,
)
logger = logging.getLogger("rpm.docker")
class DockerContextError(ConfigError):
    pass
def context_name(host_id: str) -> str:
    return f"rpm-{host_id}"
def _ssh_command(host_id: str, host: HostConfig) -> str:
    key_path = host_key_path(host_id)
    return (
        f"ssh -i {shlex.quote(str(key_path))} -p {host.port} "
        "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        "-o IdentitiesOnly=yes -o BatchMode=yes"
    )
def _ensure_known_host(host: HostConfig) -> None:
    ssh_dir = Path.home() / ".ssh"
    known_hosts = ssh_dir / "known_hosts"
    try:
        ssh_dir.mkdir(parents=True, exist_ok=True)
        ssh_dir.chmod(0o700)
    except OSError:
        return
    try:
        result = subprocess.run(
            ["ssh-keyscan", "-H", "-p", str(host.port), host.host],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except FileNotFoundError:
        logger.debug("ssh-keyscan not available; skipping known_hosts update")
        return
    if result.returncode != 0 or not result.stdout:
        logger.debug(
            "ssh-keyscan failed host=%s port=%s error=%s",
            host.host,
            host.port,
            (result.stderr or result.stdout).strip(),
        )
        return
    entries = result.stdout.strip().splitlines()
    if not entries:
        return
    existing = ""
    try:
        existing = known_hosts.read_text(encoding="utf-8")
    except OSError:
        existing = ""
    with known_hosts.open("a", encoding="utf-8") as handle:
        for entry in entries:
            if entry and entry not in existing:
                handle.write(entry + "\n")
def _ensure_ssh_config(host_id: str, host: HostConfig) -> None:
    ssh_dir = Path.home() / ".ssh"
    config_path = ssh_dir / "config"
    try:
        ssh_dir.mkdir(parents=True, exist_ok=True)
        ssh_dir.chmod(0o700)
    except OSError:
        return
    key_path = host_key_path(host_id)
    start = f"# rpm host {host_id} start"
    end = f"# rpm host {host_id} end"
    block = "\n".join(
        [
            start,
            f"Host {host.host}",
            f"  HostName {host.host}",
            f"  User {host.user}",
            f"  Port {host.port}",
            f"  IdentityFile {key_path}",
            "  IdentitiesOnly yes",
            "  StrictHostKeyChecking no",
            "  UserKnownHostsFile /dev/null",
            "  BatchMode yes",
            end,
            "",
        ]
    )
    existing = ""
    try:
        existing = config_path.read_text(encoding="utf-8")
    except OSError:
        existing = ""
    if start in existing and end in existing:
        prefix, _marker, remainder = existing.partition(start)
        _old_block, _marker_end, suffix = remainder.partition(end)
        existing = prefix + suffix.lstrip("\n")
    content = existing
    if content and not content.endswith("\n"):
        content += "\n"
    content += block
    try:
        config_path.write_text(content, encoding="utf-8")
        os.chmod(config_path, 0o600)
    except OSError:
        return
def docker_env(host_id: str, host: HostConfig) -> Dict[str, str]:
    env = os.environ.copy()
    env["DOCKER_CONFIG"] = str(config_path())
    env["DOCKER_SSH_COMMAND"] = _ssh_command(host_id, host)
    if host.docker_api_version:
        env["DOCKER_API_VERSION"] = str(host.docker_api_version).strip()
    return env
def ensure_docker_context(host_id: str, host: HostConfig) -> None:
    if not host_id:
        raise DockerContextError("Host id is required for docker context")
    if not host.ssh_key:
        raise DockerContextError("SSH key is required for docker context")
    ensure_config_dirs()
    key_path = write_host_key(host_id, host.ssh_key)
    _ensure_known_host(host)
    _ensure_ssh_config(host_id, host)
    logger.debug("Docker context key path host_id=%s path=%s", host_id, key_path)
    env = docker_env(host_id, host)
    name = context_name(host_id)
    target = f"ssh://{host.user}@{host.host}:{host.port}"
    try:
        inspect = subprocess.run(
            ["docker", "context", "inspect", name],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
    except FileNotFoundError as exc:
        raise DockerContextError("docker CLI not available") from exc
    if inspect.returncode == 0:
        cmd = ["docker", "context", "update", name, "--docker", f"host={target}"]
    else:
        cmd = [
            "docker",
            "context",
            "create",
            name,
            "--docker",
            f"host={target}",
        ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
    except FileNotFoundError as exc:
        raise DockerContextError("docker CLI not available") from exc
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip()
        raise DockerContextError(
            f"Docker context failed for {host_id}: {message or 'unknown error'}"
        )
def remove_docker_context(host_id: str) -> None:
    if not host_id:
        return
    ensure_config_dirs()
    name = context_name(host_id)
    env = os.environ.copy()
    env["DOCKER_CONFIG"] = str(config_path())
    subprocess.run(
        ["docker", "context", "rm", "-f", name],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    delete_host_key(host_id)
