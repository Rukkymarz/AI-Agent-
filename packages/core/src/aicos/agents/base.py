"""Agent contract.

Agents are PURE WORKERS: (AgentInput) -> AgentOutput. They have no handles to the
database, network, secrets or executors. Any side effect is expressed as a
ProposedAction that the orchestrator routes through policy + approvals + audit.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, Field, field_validator

from aicos.domain.identity import AGENT_FORBIDDEN_PERMISSIONS, Permission, Principal, PrincipalType
from aicos.llm.router import TaskType


class Department(StrEnum):
    EXECUTIVE = "executive"
    OPERATIONS = "operations"
    ENGINEERING = "engineering"
    DEVOPS = "devops"
    IT = "it"
    SECURITY = "security"
    PRODUCT = "product"
    SALES = "sales"
    MARKETING = "marketing"
    SUPPORT = "support"
    DATA = "data"


class AutonomyLevel(StrEnum):
    ADVISE = "advise"  # text only, no proposed actions honoured
    PROPOSE = "propose"  # may propose actions (default)


class AgentSpec(BaseModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,62}$")
    name: str
    department: Department
    description: str
    model_task: TaskType = TaskType.GENERAL
    permissions: frozenset[Permission] = frozenset()
    tools: list[str] = Field(default_factory=list)  # allowed action types, e.g. "ticket.create"
    keywords: list[str] = Field(default_factory=list)
    system_prompt: str = ""
    autonomy: AutonomyLevel = AutonomyLevel.PROPOSE
    max_actions: int = Field(default=5, ge=0, le=50)
    sandbox_profile: str = "restricted"
    reports_to: str | None = None
    source: str = "core"  # "core" or "plugin:<name>"

    @field_validator("permissions")
    @classmethod
    def _no_forbidden(cls, v: frozenset[Permission]) -> frozenset[Permission]:
        bad = v & AGENT_FORBIDDEN_PERMISSIONS
        if bad:
            raise ValueError(f"agents may not hold: {sorted(bad)}")
        return v

    def principal(self, tenant_id: str) -> Principal:
        return Principal(
            id=f"agent:{self.id}", type=PrincipalType.AGENT, tenant_id=tenant_id, permissions=self.permissions, display_name=self.name
        )


class ProposedAction(BaseModel):
    action: str = Field(pattern=r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$")
    permission: Permission
    resource: str = "*"
    payload: dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""


class AgentInput(BaseModel):
    task_id: str
    objective: str
    context: list[str] = Field(default_factory=list)  # pre-wrapped untrusted context
    policies: list[str] = Field(default_factory=list)  # human-readable policy reminders
    granted_permissions: list[Permission] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentOutput(BaseModel):
    result: str
    recommendations: list[str] = Field(default_factory=list)
    proposed_actions: list[ProposedAction] = Field(default_factory=list)
    metrics: dict[str, float | int | str] = Field(default_factory=dict)


class Agent(Protocol):
    spec: AgentSpec

    async def run(self, task: AgentInput) -> AgentOutput: ...
