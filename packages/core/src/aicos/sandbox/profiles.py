"""Agent/plugin execution sandbox: hardened container profiles.

Every profile: non-root UID, read-only rootfs, all capabilities dropped, no-new-privileges,
seccomp default profile, pid/cpu/memory limits, tmpfs scratch, no docker socket, and
network either `none` or the egress-proxy network (allow-list enforced by the proxy).
gVisor (`runsc`) is used automatically when `runtime` is set — recommended for COMMUNITY plugins.
"""

from __future__ import annotations

import asyncio
import re
from enum import StrEnum

from pydantic import BaseModel, Field

from aicos.domain.errors import SecurityViolation


class NetworkMode(StrEnum):
    NONE = "none"
    EGRESS_PROXY = "egress_proxy"


class SandboxProfile(BaseModel):
    name: str
    cpus: float = Field(default=1.0, gt=0, le=16)
    memory_mb: int = Field(default=1024, ge=64, le=65_536)
    pids: int = Field(default=256, ge=16, le=8192)
    network: NetworkMode = NetworkMode.NONE
    egress_network_name: str = "aicos-egress"
    read_only_rootfs: bool = True
    tmpfs_mb: int = Field(default=256, ge=16, le=8192)
    workspace_rw: bool = False
    timeout_s: float = Field(default=300.0, gt=0, le=7200)
    runtime: str | None = None  # e.g. "runsc" for gVisor
    user: str = "65532:65532"


PROFILES: dict[str, SandboxProfile] = {
    "restricted": SandboxProfile(name="restricted", cpus=0.5, memory_mb=512, network=NetworkMode.NONE, timeout_s=120),
    "build": SandboxProfile(
        name="build",
        cpus=2.0,
        memory_mb=4096,
        pids=1024,
        network=NetworkMode.EGRESS_PROXY,
        workspace_rw=True,
        tmpfs_mb=1024,
        timeout_s=1800,
    ),
    "research": SandboxProfile(name="research", cpus=1.0, memory_mb=2048, network=NetworkMode.EGRESS_PROXY, timeout_s=600),
    "community-plugin": SandboxProfile(
        name="community-plugin", cpus=0.5, memory_mb=512, network=NetworkMode.EGRESS_PROXY, timeout_s=60, runtime="runsc"
    ),
}

_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]*(:[A-Za-z0-9._-]+)?@sha256:[a-f0-9]{64}$")
_SAFE_PATH = re.compile(r"^/[A-Za-z0-9._/-]+$")


def docker_run_args(
    profile: SandboxProfile,
    image: str,
    command: list[str],
    *,
    workspace: str | None = None,
    env: dict[str, str] | None = None,
    name: str | None = None,
    require_digest: bool = True,
) -> list[str]:
    if require_digest and not _IMAGE.match(image):
        raise SecurityViolation("sandbox images must be pinned by sha256 digest")
    args = [
        "docker",
        "run",
        "--rm",
        "--init",
        f"--cpus={profile.cpus}",
        f"--memory={profile.memory_mb}m",
        f"--memory-swap={profile.memory_mb}m",
        f"--pids-limit={profile.pids}",
        f"--user={profile.user}",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",  # docker default seccomp applies
        "--ipc=private",
        f"--tmpfs=/tmp:rw,noexec,nosuid,size={profile.tmpfs_mb}m",
        f"--network={'none' if profile.network is NetworkMode.NONE else profile.egress_network_name}",
        f"--stop-timeout={int(min(profile.timeout_s, 30))}",
    ]
    if profile.read_only_rootfs:
        args.append("--read-only")
    if profile.runtime:
        args.append(f"--runtime={profile.runtime}")
    if name:
        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$", name):
            raise SecurityViolation("invalid container name")
        args.append(f"--name={name}")
    if workspace:
        if not _SAFE_PATH.match(workspace) or ".." in workspace or workspace.startswith(("/var/run", "/run", "/proc", "/sys", "/etc")):
            raise SecurityViolation("unsafe workspace mount")
        args.append(f"--volume={workspace}:/workspace:{'rw' if profile.workspace_rw else 'ro'}")
        args.append("--workdir=/workspace")
    for k, v in (env or {}).items():
        if not re.match(r"^[A-Z][A-Z0-9_]{0,63}$", k):
            raise SecurityViolation(f"invalid env name {k}")
        args += ["--env", f"{k}={v}"]
    return [*args, image, *command]


class SandboxResult(BaseModel):
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


class DockerSandbox:  # pragma: no cover - requires docker daemon
    def __init__(self, max_output_bytes: int = 1_000_000) -> None:
        self.max_output = max_output_bytes

    async def run(self, profile: SandboxProfile, image: str, command: list[str], **kw: object) -> SandboxResult:
        args = docker_run_args(profile, image, command, **kw)  # type: ignore[arg-type]
        proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=profile.timeout_s)
        except TimeoutError:
            proc.kill()
            return SandboxResult(exit_code=-1, stdout="", stderr="timeout", timed_out=True)
        return SandboxResult(
            exit_code=proc.returncode or 0,
            stdout=out[: self.max_output].decode(errors="replace"),
            stderr=err[: self.max_output].decode(errors="replace"),
        )
