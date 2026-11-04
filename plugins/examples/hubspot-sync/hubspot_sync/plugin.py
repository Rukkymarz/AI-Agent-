"""Reference plugin demonstrating every extension point a typical integration needs.

* registers a governed action (`hubspot_sync.upsert_contact`, requires crm:write)
* subscribes to `LeadFound` and publishes a namespaced `HubSpot.ContactQueued` event
* contributes an agent whose permissions are a subset of its manifest declaration
* reads its API token through the capability-checked secret API (never env vars)
* talks to the network only through the egress-guarded client (api.hubapi.com only)
"""

from __future__ import annotations

from typing import Any

from aicos.plugins.sdk import ActionRequest, AgentSpec, DomainEvent, Permission, Plugin, PluginContext, PluginRegistrar

HUBSPOT = "https://api.hubapi.com/crm/v3/objects/contacts"


class HubSpotSyncPlugin(Plugin):
    def __init__(self) -> None:
        self.ctx: PluginContext | None = None

    def activate(self, ctx: PluginContext, registrar: PluginRegistrar) -> None:
        self.ctx = ctx
        registrar.register_action("hubspot_sync.upsert_contact", Permission.CRM_WRITE, self.upsert_contact)
        registrar.subscribe("LeadFound", self.on_lead_found)
        registrar.register_agent(
            AgentSpec(
                id="hubspot-sync-enricher",
                name="HubSpot Enrichment Agent",
                department="sales",
                description="Normalises lead data and proposes HubSpot upserts.",
                model_task="business",
                permissions=frozenset({"task:read", "knowledge:read", "crm:write"}),
                tools=["hubspot_sync.upsert_contact"],
                keywords=["hubspot", "crm sync"],
            )
        )

    async def on_lead_found(self, event: DomainEvent) -> None:
        assert self.ctx is not None
        email = str(event.payload.get("email", "")).strip().lower()
        if email:
            await self.ctx.publish("HubSpot.ContactQueued", {"email": email}, correlation_id=event.id)

    async def upsert_contact(self, req: ActionRequest) -> dict[str, Any]:
        assert self.ctx is not None
        token = self.ctx.secret("plugins/hubspot/token")
        props = {k: v for k, v in req.payload.items() if k in {"email", "firstname", "lastname", "company"}}
        async with self.ctx.http() as client:
            r = await client.post(HUBSPOT, json={"properties": props}, headers={"Authorization": f"Bearer {token}"})
            r.raise_for_status()
            return {"status": "upserted", "hubspot_id": r.json().get("id")}

    def deactivate(self) -> None:
        self.ctx = None
