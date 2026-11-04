"""Action catalog + executor.

The PLATFORM decides which permission an action type requires — never the agent.
Execution is dispatched through handlers. The default handler writes a signed command
to the outbox and emits ActionExecuted; integration workers (n8n, GitHub, CRM) consume it.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from aicos.domain.common import new_id, utcnow
from aicos.domain.errors import ValidationFailed
from aicos.domain.identity import Permission
from aicos.events.bus import DomainEvent, EventBus, EventType
from aicos.security.policy import ActionRequest

P = Permission

ACTION_PERMISSIONS: dict[str, Permission] = {
    "report.publish": P.TASK_READ,
    "adr.create": P.TASK_READ,
    "code.review_comment": P.TASK_READ,
    "ticket.create": P.TICKET_WRITE,
    "ticket.comment": P.TICKET_WRITE,
    "ticket.reply_draft": P.TICKET_WRITE,
    "access.request": P.TICKET_WRITE,
    "policy.propose": P.TICKET_WRITE,
    "workflow.trigger": P.EVENT_PUBLISH,
    "workflow.propose": P.EVENT_PUBLISH,
    "security.alert": P.EVENT_PUBLISH,
    "incident.declare": P.EVENT_PUBLISH,
    "code.pull_request": P.CODE_PR_CREATE,
    "code.merge": P.CODE_MERGE,
    "content.draft": P.CONTENT_DRAFT,
    "social.schedule": P.CONTENT_DRAFT,
    "social.post": P.SOCIAL_PUBLISH,
    "proposal.generate": P.CONTENT_DRAFT,
    "video.script": P.CONTENT_DRAFT,
    "email.send_single": P.CONTENT_DRAFT,
    "campaign.send": P.EMAIL_MASS_SEND,
    "crm.update": P.CRM_WRITE,
    "crm.create_lead": P.CRM_WRITE,
    "contract.send": P.CONTRACT_SIGN,
    "web.search": P.WEB_RESEARCH,
    "knowledge.article_propose": P.KNOWLEDGE_WRITE,
    "sql.query_readonly": P.KNOWLEDGE_READ,
    "deploy.staging": P.DEPLOY_STAGING,
    "deploy.production": P.DEPLOY_PRODUCTION,
    "infra.apply": P.INFRA_CHANGE,
    "db.migrate": P.DB_SCHEMA_CHANGE,
    "finance.payment": P.FINANCE_EXECUTE,
    "secret.read": P.SECRET_READ,
    "user.delete": P.USER_DELETE,
    "permission.change": P.PERMISSION_CHANGE,
    "policy.update": P.POLICY_WRITE,
}

Handler = Callable[[ActionRequest], Awaitable[dict[str, Any]]]


class ActionExecutor:
    def __init__(self, bus: EventBus) -> None:
        self._bus = bus
        self._handlers: dict[str, Handler] = {}
        self._permissions: dict[str, Permission] = dict(ACTION_PERMISSIONS)
        self.outbox: list[dict[str, Any]] = []

    def required_permission(self, action: str) -> Permission | None:
        return self._permissions.get(action)

    def register_action(self, action: str, permission: Permission, handler: Handler | None = None) -> None:
        existing = self._permissions.get(action)
        if existing is not None and existing != permission:
            raise ValidationFailed(f"action '{action}' already bound to {existing}")
        self._permissions[action] = permission
        if handler:
            self._handlers[action] = handler

    def unregister_action(self, action: str) -> None:
        if action in ACTION_PERMISSIONS:
            raise ValidationFailed("core actions cannot be unregistered")
        self._permissions.pop(action, None)
        self._handlers.pop(action, None)

    def register_handler(self, action: str, handler: Handler) -> None:
        if action not in self._permissions:
            raise ValidationFailed(f"unknown action '{action}'")
        self._handlers[action] = handler

    async def _outbox(self, req: ActionRequest) -> dict[str, Any]:
        cmd = {
            "id": new_id("cmd"),
            "ts": utcnow().isoformat(),
            "action": req.action,
            "resource": req.resource,
            "payload": req.payload,
            "actor": req.actor.id,
            "on_behalf_of": req.on_behalf_of.id if req.on_behalf_of else None,
            "payload_hash": req.payload_hash(),
        }
        self.outbox.append(cmd)
        return {"status": "dispatched", "command_id": cmd["id"]}

    async def execute(self, req: ActionRequest) -> dict[str, Any]:
        handler = self._handlers.get(req.action, self._outbox)
        result = await handler(req)
        await self._bus.publish(
            DomainEvent(
                type=EventType.ACTION_EXECUTED,
                tenant_id=req.tenant_id,
                source="action-executor",
                correlation_id=req.id,
                payload={"action": req.action, "resource": req.resource, "result": result},
            )
        )
        return result
