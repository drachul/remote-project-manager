from dataclasses import dataclass
import io
import logging
import re
import time
from typing import Iterator, Tuple

import paramiko

from .config import HostConfig


@dataclass
class SSHResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str


class SSHError(RuntimeError):
    pass


class SSHCancelled(SSHError):
    pass


logger = logging.getLogger("rpm.ssh")


def _format_target(host: HostConfig) -> str:
    return f"{host.user}@{host.host}:{host.port}"


def _redact_command(command: str) -> str:
    redacted = re.sub(r"(RSYNC_PASSWORD=)(\\S+)", r"\\1***", command)
    redacted = re.sub(r"(sshpass\\s+-p\\s+)(\\S+)", r"\\1***", redacted)
    return redacted


def _connect(host: HostConfig, timeout: int) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    pkey = None
    if host.ssh_key:
        key_text = host.ssh_key
        key_classes = []
        for name in ("RSAKey", "ECDSAKey", "Ed25519Key", "DSSKey"):
            key_cls = getattr(paramiko, name, None)
            if key_cls:
                key_classes.append(key_cls)
        key_error = None
        for key_cls in key_classes:
            try:
                pkey = key_cls.from_private_key(io.StringIO(key_text))
                break
            except Exception as exc:
                key_error = exc
                continue
        if pkey is None:
            raise SSHError(f"SSH key parse failed: {key_error}")
    client.connect(
        hostname=host.host,
        username=host.user,
        key_filename=host.ssh_key_path,
        pkey=pkey,
        port=host.port,
        timeout=timeout,
        allow_agent=False,
        look_for_keys=False,
    )
    return client


def run_ssh_command(host: HostConfig, command: str, timeout: int = 60) -> SSHResult:
    try:
        logger.debug("SSH exec %s: %s", _format_target(host), _redact_command(command))
        client = _connect(host, timeout)
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        stdout_text = stdout.read().decode("utf-8", errors="replace")
        stderr_text = stderr.read().decode("utf-8", errors="replace")
    except Exception as exc:
        raise SSHError(f"SSH command failed: {exc}") from exc
    finally:
        if "client" in locals():
            client.close()

    return SSHResult(
        command=command,
        exit_code=exit_code,
        stdout=stdout_text.strip(),
        stderr=stderr_text.strip(),
    )


def run_ssh_command_cancelable(
    host: HostConfig,
    command: str,
    stop_event,
    timeout: int = 60,
    chunk_size: int = 4096,
) -> SSHResult:
    if stop_event.is_set():
        raise SSHCancelled("SSH command cancelled")
    try:
        logger.debug("SSH exec %s: %s", _format_target(host), _redact_command(command))
        client = _connect(host, timeout)
        transport = client.get_transport()
        if not transport:
            raise SSHError("SSH transport unavailable")
        channel = transport.open_session()
        channel.settimeout(1.0)
        channel.exec_command(command)
        stdout_chunks = []
        stderr_chunks = []

        while True:
            if stop_event.is_set():
                channel.close()
                raise SSHCancelled("SSH command cancelled")
            made_progress = False
            if channel.recv_ready():
                data = channel.recv(chunk_size)
                if data:
                    stdout_chunks.append(data)
                    made_progress = True
            if channel.recv_stderr_ready():
                data = channel.recv_stderr(chunk_size)
                if data:
                    stderr_chunks.append(data)
                    made_progress = True
            if channel.exit_status_ready():
                break
            if not made_progress:
                time.sleep(0.1)

        while channel.recv_ready():
            data = channel.recv(chunk_size)
            if not data:
                break
            stdout_chunks.append(data)
        while channel.recv_stderr_ready():
            data = channel.recv_stderr(chunk_size)
            if not data:
                break
            stderr_chunks.append(data)

        exit_code = channel.recv_exit_status()
        stdout_text = b"".join(stdout_chunks).decode("utf-8", errors="replace")
        stderr_text = b"".join(stderr_chunks).decode("utf-8", errors="replace")
    except SSHCancelled:
        raise
    except Exception as exc:
        raise SSHError(f"SSH command failed: {exc}") from exc
    finally:
        if "channel" in locals():
            channel.close()
        if "client" in locals():
            client.close()

    return SSHResult(
        command=command,
        exit_code=exit_code,
        stdout=stdout_text.strip(),
        stderr=stderr_text.strip(),
    )


def read_remote_file(host: HostConfig, path: str, timeout: int = 60) -> str:
    try:
        client = _connect(host, timeout)
        sftp = client.open_sftp()
        with sftp.open(path, "r") as handle:
            data = handle.read()
        if isinstance(data, str):
            return data
        return data.decode("utf-8", errors="replace")
    except Exception as exc:
        raise SSHError(f"SSH read failed: {exc}") from exc
    finally:
        if "client" in locals():
            client.close()


def write_remote_file(host: HostConfig, path: str, content: str, timeout: int = 60) -> None:
    try:
        client = _connect(host, timeout)
        sftp = client.open_sftp()
        data = content.encode("utf-8")
        with sftp.open(path, "w") as handle:
            handle.write(data)
            handle.flush()
    except Exception as exc:
        raise SSHError(f"SSH write failed: {exc}") from exc
    finally:
        if "client" in locals():
            client.close()


def stream_ssh_command(
    host: HostConfig,
    command: str,
    stop_event,
    timeout: int = 60,
    chunk_size: int = 4096,
) -> Iterator[Tuple[str, str]]:
    try:
        logger.debug("SSH stream %s: %s", _format_target(host), _redact_command(command))
        client = _connect(host, timeout)
        transport = client.get_transport()
        if not transport:
            raise SSHError("SSH transport unavailable")
        channel = transport.open_session()
        channel.set_combine_stderr(False)
        channel.settimeout(1.0)
        channel.exec_command(command)
        stdout_buffer = b""
        stderr_buffer = b""

        while True:
            if stop_event.is_set():
                break
            made_progress = False
            if channel.recv_ready():
                data = channel.recv(chunk_size)
                if data:
                    stdout_buffer += data
                    made_progress = True
                    while b"\n" in stdout_buffer:
                        line, stdout_buffer = stdout_buffer.split(b"\n", 1)
                        yield ("stdout", line.decode("utf-8", errors="replace"))
            if channel.recv_stderr_ready():
                data = channel.recv_stderr(chunk_size)
                if data:
                    stderr_buffer += data
                    made_progress = True
                    while b"\n" in stderr_buffer:
                        line, stderr_buffer = stderr_buffer.split(b"\n", 1)
                        yield ("stderr", line.decode("utf-8", errors="replace"))
            if not made_progress:
                if channel.exit_status_ready():
                    break
                time.sleep(0.1)

        if stdout_buffer:
            yield ("stdout", stdout_buffer.decode("utf-8", errors="replace"))
        if stderr_buffer:
            yield ("stderr", stderr_buffer.decode("utf-8", errors="replace"))
    except Exception as exc:
        raise SSHError(f"SSH stream failed: {exc}") from exc
    finally:
        if "channel" in locals():
            channel.close()
        if "client" in locals():
            client.close()


def open_ssh_shell(
    host: HostConfig,
    command: str,
    timeout: int = 60,
    cols: int = 80,
    rows: int = 24,
) -> Tuple[paramiko.SSHClient, paramiko.Channel]:
    client = _connect(host, timeout)
    try:
        transport = client.get_transport()
        if not transport:
            raise SSHError("SSH transport unavailable")
        channel = transport.open_session()
        channel.get_pty(term="xterm-256color", width=cols, height=rows)
        channel.exec_command(command)
        return client, channel
    except Exception:
        client.close()
        raise
