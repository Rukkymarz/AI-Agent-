"""
title: AICOMPANY-OS Agents
description: Routes Open WebUI chats through the governed AICOMPANY-OS orchestrator (firewall, RBAC, approvals, audit).
version: 0.1.0
license: MIT
requirements: httpx

Install: Open WebUI -> Admin -> Functions -> + -> paste this file. Each agent appears as a model ("AICOS: <Agent>").
Auth: forwards the user's OIDC access token (Open WebUI must use the same Keycloak realm), so the API applies
the *user's* RBAC — the pipe holds no privileged credentials.
"""

from __future__ import annotations

from typing import Any

import httpx
from pydantic import BaseModel, Field


class Pipe:
    class Valves(BaseModel):
        AICOS_API_URL: str = Field(default="http://aicos-api:8000")
        TIMEOUT_S: float = Field(default=300)
        SHOW_ACTIONS: bool = Field(default=True)
        AGENT_IDS: str = Field(
            default="coo,ceo,cto,software-engineer,support-agent,seo-agent,research-agent,data-analyst",
            description="Comma-separated agent ids exposed as models (listing requires a user token)",
        )

    def __init__(self) -> None:
        self.type = "manifold"
        self.valves = self.Valves()

    def _token(self, __request__: Any) -> str:
        auth = __request__.headers.get("authorization", "") if __request__ else ""
        token = __request__.cookies.get("oauth_id_token", "") if __request__ else ""
        return auth.removeprefix("Bearer ").strip() or token

    def pipes(self) -> list[dict[str, str]]:
        ids = [i.strip() for i in self.valves.AGENT_IDS.split(",") if i.strip()]
        return [{"id": "auto", "name": "AICOS: Auto-route"}] + [{"id": i, "name": "AICOS: " + i.replace("-", " ").title()} for i in ids]

    async def pipe(self, body: dict[str, Any], __user__: dict[str, Any] | None = None, __request__: Any = None) -> str:
        model_id = body.get("model", "").split(".", 1)[-1]
        messages = body.get("messages", [])
        objective = next((m["content"] for m in reversed(messages) if m.get("role") == "user"), "")
        if isinstance(objective, list):  # multimodal parts
            objective = " ".join(p.get("text", "") for p in objective if isinstance(p, dict))
        payload: dict[str, Any] = {"objective": objective, "conversation_id": body.get("chat_id")}
        if model_id and model_id != "auto":
            payload["agent_id"] = model_id
        async with httpx.AsyncClient(timeout=self.valves.TIMEOUT_S) as c:
            r = await c.post(
                f"{self.valves.AICOS_API_URL}/v1/tasks", json=payload, headers={"Authorization": f"Bearer {self._token(__request__)}"}
            )
        if r.status_code != 200:
            return f"**AICOS error {r.status_code}:** {r.json().get('detail', r.text)}"
        res = r.json()
        if res["status"] != "completed":
            return f"**Request {res['status']}:** {res.get('error') or 'blocked by policy'}"
        out = [res["output"]]
        if res.get("recommendations"):
            out.append("\n**Recommendations**\n" + "\n".join(f"- {x}" for x in res["recommendations"]))
        if self.valves.SHOW_ACTIONS and res.get("actions"):
            icon = {"executed": "✅", "pending_approval": "⏳", "denied": "⛔", "failed": "❌"}
            rows = [
                f"- {icon.get(a['status'], '•')} `{a['action']}` — {a['status']}"
                + (f" (proposal `{a['proposal_id']}`)" if a.get("proposal_id") else "")
                for a in res["actions"]
            ]
            out.append("\n**Actions**\n" + "\n".join(rows))
        out.append(f"\n<sub>agent: {res['agent_id']} · task: {res['task_id']}</sub>")
        return "\n".join(out)
