"""Child-process runner: injects secrets, streams redacted output, kills groups."""

from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from envvault.models import Project
from envvault.runtime import ExecRecord, Runtime
from envvault.services import audit, envfile
from envvault.services.redact import Redactor

MAX_LINE_BUFFER = 64 * 1024
SSE_KEEPALIVE_SECONDS = 15
MAX_ENV_OVERRIDES = 64
MAX_ENV_KEY_LENGTH = 120
MAX_ENV_VALUE_BYTES = 64 * 1024
MAX_ENV_TOTAL_BYTES = 256 * 1024
RESERVED_ENV_PREFIX = "ENVVAULT_"


class ExecError(ValueError):
    """Raised for invalid commands or working directories."""


def resolve_cwd(project: Project, requested: str | None) -> Path:
    """Resolve a working directory and require it to stay inside the project."""
    base = Path(project.path).expanduser().resolve()
    cwd = Path(requested).expanduser().resolve() if requested else base
    if not cwd.is_relative_to(base):
        raise ExecError(f"cwd must be inside {base}")
    if not cwd.is_dir():
        raise ExecError(f"cwd does not exist: {cwd}")
    return cwd


def validate_command(command: list[str]) -> list[str]:
    """Validate argv without invoking a shell."""
    if not command:
        raise ExecError("command is required")
    cleaned = []
    for part in command:
        if not isinstance(part, str):
            raise ExecError("command must be a list of strings")
        if "\x00" in part:
            raise ExecError("command contains a null byte")
        if len(part) > 4096:
            raise ExecError("command argument is too long")
        cleaned.append(part)
    return cleaned


def validate_env(
    overrides: dict[str, str] | None, *, vault_keys: set[str] | None = None
) -> dict[str, str]:
    """Validate non-secret environment overrides sent with an exec request.

    Overrides are merged into the child environment by the daemon. Vault keys
    win by construction: a request that tries to redefine one is rejected
    instead of silently shadowing the stored secret.
    """
    if not overrides:
        return {}
    if len(overrides) > MAX_ENV_OVERRIDES:
        raise ExecError(f"at most {MAX_ENV_OVERRIDES} environment overrides")
    cleaned: dict[str, str] = {}
    total = 0
    for key, value in overrides.items():
        if (
            not isinstance(key, str)
            or len(key) > MAX_ENV_KEY_LENGTH
            or not envfile.KEY_PATTERN.match(key)
        ):
            raise ExecError(f"invalid environment key: {key!r}")
        if key.startswith(RESERVED_ENV_PREFIX):
            raise ExecError(f"environment key is reserved: {key}")
        if not isinstance(value, str):
            raise ExecError(f"environment value for {key} must be a string")
        size = len(value.encode("utf-8"))
        if size > MAX_ENV_VALUE_BYTES:
            raise ExecError(f"environment value for {key} is too large")
        total += size
        cleaned[key] = value
    if total > MAX_ENV_TOTAL_BYTES:
        raise ExecError("environment overrides are too large")
    if vault_keys:
        collisions = sorted(set(cleaned) & vault_keys)
        if collisions:
            raise ExecError("cannot override vault keys: " + ", ".join(collisions))
    return cleaned


def spawn(
    state: Runtime,
    *,
    project: Project,
    environment: str,
    secrets: dict[str, str],
    command: list[str],
    cwd: Path,
    actor_type: str,
    actor_name: str,
    extra_env: dict[str, str] | None = None,
    timeout_seconds: int | None = None,
) -> tuple[ExecRecord, Redactor]:
    """Start the child with secrets in its environment and no ENVVAULT_* leak."""
    command = validate_command(command)
    extra_env = validate_env(extra_env, vault_keys=set(secrets))
    base_env = {key: value for key, value in os.environ.items() if not key.startswith("ENVVAULT_")}
    base_env.update(secrets)
    base_env.update(extra_env)
    base_env["ENVVAULT_PROJECT"] = project.slug
    base_env["ENVVAULT_ENV"] = environment
    try:
        process = subprocess.Popen(
            command,
            cwd=str(cwd),
            env=base_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            bufsize=0,
        )
    except OSError as exc:
        raise ExecError(f"could not start command: {exc.strerror}") from exc
    record = ExecRecord(
        exec_id=uuid.uuid4().hex[:16],
        process=process,
        actor_type=actor_type,
        actor_name=actor_name,
        project_slug=project.slug,
        environment=environment,
        command=" ".join(command),
        env_keys=tuple(sorted(extra_env)),
        timeout_seconds=timeout_seconds,
    )
    state.add_exec(record)
    return record, Redactor(secrets)


def stream(
    factory: sessionmaker[Session],
    state: Runtime,
    record: ExecRecord,
    redactor: Redactor,
) -> Iterator[str]:
    """Yield SSE events until the child exits or the client disconnects.

    The daemon redacts every chunk before it leaves the process; plaintext is
    never serialized into the response.
    """
    output: queue.Queue[str | tuple[str, int, int] | None] = queue.Queue()
    reader = threading.Thread(
        target=_read_output,
        args=(record, redactor, output),
        name=f"exec-{record.exec_id}",
        daemon=True,
    )
    reader.start()
    yield _event(
        {
            "type": "start",
            "exec_id": record.exec_id,
            "project": record.project_slug,
            "environment": record.environment,
            "command": record.command,
            "env_keys": list(record.env_keys),
            "timeout_seconds": record.timeout_seconds,
        }
    )
    exit_code: int | None = None
    duration_ms = 0
    finished = False
    timed_out = False
    deadline = record.started_at + record.timeout_seconds if record.timeout_seconds else None
    try:
        while True:
            wait = SSE_KEEPALIVE_SECONDS
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    if not timed_out:
                        timed_out = True
                        from envvault.runtime import _terminate_process_group

                        _terminate_process_group(record.process)
                    wait = 0.1
                else:
                    wait = min(wait, remaining)
            try:
                item = output.get(timeout=max(wait, 0.1))
            except queue.Empty:
                yield ": ping\n\n"
                continue
            if item is None:
                break
            if isinstance(item, tuple):
                _, exit_code, duration_ms = item
                break
            yield _event({"type": "output", "text": item})
        finished = True
        yield _event(
            {
                "type": "exit",
                "exec_id": record.exec_id,
                "code": exit_code,
                "duration_ms": duration_ms,
                "timed_out": timed_out,
            }
        )
    finally:
        state.remove_exec(record.exec_id)
        if record.process.poll() is None:
            from envvault.runtime import _terminate_process_group

            _terminate_process_group(record.process)
        with factory() as db:
            audit.append(
                db,
                actor_type=record.actor_type,
                actor_name=record.actor_name,
                action="exec.finish" if finished else "exec.cancel",
                project_slug=record.project_slug,
                environment=record.environment,
                command=record.command,
                result="ok" if finished and exit_code == 0 else "error",
                detail={
                    "exec_id": record.exec_id,
                    "exit_code": exit_code,
                    "duration_ms": duration_ms,
                    "redacted_patterns": redactor.pattern_count,
                    "env_keys": list(record.env_keys),
                    "timed_out": timed_out,
                },
                lock=state.lock,
            )
            db.commit()


def _read_output(
    record: ExecRecord,
    redactor: Redactor,
    output: queue.Queue[str | tuple[str, int, int] | None],
) -> None:
    """Read the merged stdout/stderr pipe and push redacted lines."""
    started = time.monotonic()
    stdout = record.process.stdout
    assert stdout is not None
    fd = stdout.fileno()
    buffer = b""
    keep = max(redactor.max_pattern_length - 1, 0)
    try:
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                output.put(redactor.redact(line.decode("utf-8", "replace")) + "\n")
            if len(buffer) > MAX_LINE_BUFFER and keep:
                safe, buffer = buffer[:-keep], buffer[-keep:]
                output.put(redactor.redact(safe.decode("utf-8", "replace")))
        if buffer:
            output.put(redactor.redact(buffer.decode("utf-8", "replace")))
    finally:
        code = record.process.wait()
        output.put(("exit", code, int((time.monotonic() - started) * 1000)))
        output.put(None)
        stdout.close()


def _event(payload: dict[str, Any]) -> str:
    """Encode one SSE data frame."""
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
