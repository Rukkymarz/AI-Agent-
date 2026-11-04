"""Identity primitives: principals, roles, permissions.

Permissions are `resource:action` strings. Roles are coarse bundles; agents never
receive roles — they receive an explicit, minimal permission set from their spec.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Permission(StrEnum):
    # read surface
    TASK_READ = "task:read"
    AGENT_READ = "agent:read"
    APPROVAL_READ = "approval:read"
    KNOWLEDGE_READ = "knowledge:read"
    MEMORY_READ = "memory:read"
    PLUGIN_READ = "plugin:read"
    POLICY_READ = "policy:read"
    AUDIT_READ = "audit:read"
    # operate
    TASK_SUBMIT = "task:submit"
    AGENT_INVOKE = "agent:invoke"
    KNOWLEDGE_WRITE = "knowledge:write"
    MEMORY_WRITE = "memory:write"
    EVENT_PUBLISH = "event:publish"
    CODE_PR_CREATE = "code:pr_create"
    TICKET_WRITE = "ticket:write"
    CRM_WRITE = "crm:write"
    CONTENT_DRAFT = "content:draft"
    WEB_RESEARCH = "web:research"
    DEPLOY_STAGING = "deploy:staging"
    # govern
    APPROVAL_DECIDE = "approval:decide"
    COMPLIANCE_REPORT = "compliance:report"
    AGENT_MANAGE = "agent:manage"
    # critical (always gated by the approval gateway)
    DEPLOY_PRODUCTION = "deploy:production"
    INFRA_CHANGE = "infra:change"
    PERMISSION_CHANGE = "permission:change"
    USER_MANAGE = "user:manage"
    USER_DELETE = "user:delete"
    SECRET_READ = "secret:read"  # noqa: S105 - permission name
    DB_SCHEMA_CHANGE = "db:schema_change"
    EMAIL_MASS_SEND = "email:mass_send"
    FINANCE_EXECUTE = "finance:execute"
    CONTRACT_SIGN = "contract:sign"
    CODE_MERGE = "code:merge"
    POLICY_WRITE = "policy:write"
    PLUGIN_INSTALL = "plugin:install"
    PLUGIN_MANAGE = "plugin:manage"
    TENANT_MANAGE = "tenant:manage"


CRITICAL_PERMISSIONS: frozenset[Permission] = frozenset(
    {
        Permission.DEPLOY_PRODUCTION,
        Permission.INFRA_CHANGE,
        Permission.PERMISSION_CHANGE,
        Permission.USER_DELETE,
        Permission.SECRET_READ,
        Permission.DB_SCHEMA_CHANGE,
        Permission.EMAIL_MASS_SEND,
        Permission.FINANCE_EXECUTE,
        Permission.CONTRACT_SIGN,
        Permission.CODE_MERGE,
        Permission.POLICY_WRITE,
        Permission.PLUGIN_INSTALL,
        Permission.TENANT_MANAGE,
    }
)

# Permissions an agent may NEVER hold, regardless of spec or plugin grant.
AGENT_FORBIDDEN_PERMISSIONS: frozenset[Permission] = frozenset(
    {
        Permission.APPROVAL_DECIDE,
        Permission.POLICY_WRITE,
        Permission.PERMISSION_CHANGE,
        Permission.USER_DELETE,
        Permission.USER_MANAGE,
        Permission.PLUGIN_INSTALL,
        Permission.PLUGIN_MANAGE,
        Permission.TENANT_MANAGE,
        Permission.AGENT_MANAGE,
    }
)


class Role(StrEnum):
    SUPER_ADMIN = "SuperAdmin"
    ADMIN = "Admin"
    MANAGER = "Manager"
    OPERATOR = "Operator"
    REVIEWER = "Reviewer"
    VIEWER = "Viewer"


class PrincipalType(StrEnum):
    HUMAN = "human"
    AGENT = "agent"
    SERVICE = "service"


class Principal(BaseModel):
    """An authenticated actor. Immutable once constructed."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(min_length=1, max_length=200)
    type: PrincipalType
    tenant_id: str = Field(default="default", min_length=1, max_length=100)
    roles: frozenset[Role] = frozenset()
    # Explicit grants (agents/services). Humans normally derive from roles.
    permissions: frozenset[Permission] = frozenset()
    mfa_verified: bool = False
    display_name: str | None = None

    @property
    def is_human(self) -> bool:
        return self.type is PrincipalType.HUMAN

    @property
    def is_agent(self) -> bool:
        return self.type is PrincipalType.AGENT
