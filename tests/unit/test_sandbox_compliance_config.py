from __future__ import annotations

import pytest
from pydantic import ValidationError

from aicos.compliance.controls import ComplianceState, ControlStatus, Framework, generate_report
from aicos.config import Settings
from aicos.container import Container
from aicos.domain.common import canonical_json
from aicos.domain.errors import SecurityViolation
from aicos.sandbox.profiles import PROFILES, docker_run_args

DIGEST = "ghcr.io/aicompany-os/agent-runtime:1.0@sha256:" + "a" * 64


def test_restricted_profile_hardening() -> None:
    args = docker_run_args(PROFILES["restricted"], DIGEST, ["python", "-m", "worker"], env={"TASK_ID": "t1"})
    for flag in [
        "--cap-drop=ALL",
        "--read-only",
        "--network=none",
        "--user=65532:65532",
        "--pids-limit=256",
        "--security-opt=no-new-privileges:true",
        "--memory=512m",
        "--cpus=0.5",
        "--ipc=private",
    ]:
        assert flag in args, flag
    assert args[-3:] == ["python", "-m", "worker"]
    assert not any("docker.sock" in a for a in args)


def test_build_and_community_profiles() -> None:
    build = docker_run_args(PROFILES["build"], DIGEST, ["make"], workspace="/srv/ws/task1", name="task-1")
    assert "--network=aicos-egress" in build and "--volume=/srv/ws/task1:/workspace:rw" in build
    assert "--runtime=runsc" in docker_run_args(PROFILES["community-plugin"], DIGEST, ["run"])


@pytest.mark.parametrize(
    "kw",
    [
        {"image": "python:latest"},
        {"workspace": "/var/run/docker.sock"},
        {"workspace": "/srv/../etc"},
        {"workspace": "relative"},
        {"env": {"bad-name": "x"}},
        {"name": "bad name!"},
    ],
)
def test_sandbox_rejects_unsafe(kw: dict[str, object]) -> None:
    image = str(kw.pop("image", DIGEST))
    with pytest.raises(SecurityViolation):
        docker_run_args(PROFILES["build"], image, ["x"], **kw)  # type: ignore[arg-type]


def test_compliance_report_frameworks(container: Container) -> None:
    state = ComplianceState(
        audit=container.audit,
        approvals=container.approvals,
        policy=container.policy,
        tenant_id="default",
        settings={"require_mfa": True, "tls_enabled": True, "encryption_at_rest": True, "data_retention_days": 30},
    )
    full = generate_report(state)
    assert full.summary[ControlStatus.FAIL] == 0 and full.summary[ControlStatus.MANUAL] == 1
    owasp = generate_report(state, Framework.OWASP_LLM)
    assert {c.id for c in owasp.controls} == {"CHG-1", "IAM-1", "AI-1"}
    weak = generate_report(
        ComplianceState(
            audit=container.audit,
            approvals=container.approvals,
            policy=container.policy,
            tenant_id="default",
            settings={"require_mfa": False},
        )
    )
    assert {c.id for c in weak.controls if c.status is ControlStatus.FAIL} == {"IAM-2", "CRY-1"}
    assert "| AUD-1 |" in full.to_markdown()


def test_production_guardrails() -> None:
    with pytest.raises(ValidationError, match="insecure configuration"):
        Settings(env="production", auth_mode="dev")
    with pytest.raises(ValidationError, match="tls_enabled"):
        Settings(env="production", audit_hmac_key="a" * 40, approval_signing_key="b" * 40)
    with pytest.raises(ValidationError, match="development only"):
        Settings(env="staging", audit_hmac_key="a" * 40, approval_signing_key="b" * 40, llm_provider="echo")
    with pytest.raises(ValidationError, match=">= 32 bytes"):
        Settings(audit_hmac_key="short")
    ok = Settings(env="production", audit_hmac_key="a" * 40, approval_signing_key="b" * 40, tls_enabled=True)
    assert ok.key("audit_hmac_key") == b"a" * 40
    dev = Settings(env="development")
    assert len(dev.key("approval_signing_key")) >= 32


def test_canonical_json_types() -> None:
    from datetime import UTC, datetime

    from aicos.domain.identity import Principal, PrincipalType

    p = Principal(id="x", type=PrincipalType.HUMAN)
    out = canonical_json({"b": {2, 1}, "a": datetime(2026, 1, 1, tzinfo=UTC), "p": p, "o": object})
    assert out.startswith('{"a":"2026-01-01T00:00:00+00:00","b":["1","2"]')
