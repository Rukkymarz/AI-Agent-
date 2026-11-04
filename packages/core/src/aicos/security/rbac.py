"""Role-based access control with agent least-privilege and confused-deputy protection."""

from __future__ import annotations

from aicos.domain.identity import (
    AGENT_FORBIDDEN_PERMISSIONS,
    Permission,
    Principal,
    PrincipalType,
    Role,
)

P = Permission

_VIEWER = frozenset({P.TASK_READ, P.AGENT_READ, P.APPROVAL_READ, P.KNOWLEDGE_READ, P.PLUGIN_READ, P.POLICY_READ})
_REVIEWER = _VIEWER | {P.APPROVAL_DECIDE, P.AUDIT_READ, P.COMPLIANCE_REPORT}
_OPERATOR = _VIEWER | {
    P.TASK_SUBMIT,
    P.AGENT_INVOKE,
    P.KNOWLEDGE_WRITE,
    P.MEMORY_READ,
    P.MEMORY_WRITE,
    P.EVENT_PUBLISH,
    P.CODE_PR_CREATE,
    P.TICKET_WRITE,
    P.CRM_WRITE,
    P.CONTENT_DRAFT,
    P.WEB_RESEARCH,
    P.DEPLOY_STAGING,
}
_MANAGER = _OPERATOR | _REVIEWER | {P.AGENT_MANAGE, P.EMAIL_MASS_SEND, P.CONTRACT_SIGN}
_ADMIN = _MANAGER | {
    P.DEPLOY_PRODUCTION,
    P.INFRA_CHANGE,
    P.PERMISSION_CHANGE,
    P.USER_MANAGE,
    P.SECRET_READ,
    P.DB_SCHEMA_CHANGE,
    P.FINANCE_EXECUTE,
    P.CODE_MERGE,
    P.PLUGIN_INSTALL,
    P.PLUGIN_MANAGE,
}
_SUPER = frozenset(Permission)

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset(_VIEWER),
    Role.REVIEWER: frozenset(_REVIEWER),
    Role.OPERATOR: frozenset(_OPERATOR),
    Role.MANAGER: frozenset(_MANAGER),
    Role.ADMIN: frozenset(_ADMIN),
    Role.SUPER_ADMIN: _SUPER,
}


def effective_permissions(principal: Principal) -> frozenset[Permission]:
    """Permissions a principal holds on its own (no delegation)."""
    if principal.type is PrincipalType.AGENT:
        # Agents: explicit grants only, roles ignored, forbidden set stripped.
        return frozenset(principal.permissions - AGENT_FORBIDDEN_PERMISSIONS)
    perms: set[Permission] = set(principal.permissions)
    for role in principal.roles:
        perms |= ROLE_PERMISSIONS.get(role, frozenset())
    return frozenset(perms)


def delegated_permissions(actor: Principal, on_behalf_of: Principal | None) -> frozenset[Permission]:
    """Agent acting for a human gets the INTERSECTION of both (confused-deputy guard)."""
    own = effective_permissions(actor)
    if actor.type is PrincipalType.AGENT:
        if on_behalf_of is None or on_behalf_of.type is not PrincipalType.HUMAN:
            return frozenset()  # agents must always act on behalf of a human
        if on_behalf_of.tenant_id != actor.tenant_id:
            return frozenset()
        return own & effective_permissions(on_behalf_of)
    return own


def has_permission(principal: Principal, permission: Permission) -> bool:
    return permission in effective_permissions(principal)
