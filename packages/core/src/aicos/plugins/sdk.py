"""Public plugin SDK surface. Plugin authors import ONLY from here.

from aicos.plugins.sdk import Plugin, PluginContext, PluginRegistrar

class MyPlugin(Plugin):
    def activate(self, ctx, reg):
        reg.register_action("my_plugin.do_thing", Permission.CRM_WRITE, self.do_thing)
        reg.subscribe("LeadFound", self.on_lead)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from aicos.agents.base import AgentInput, AgentOutput, AgentSpec, ProposedAction
from aicos.domain.identity import Permission
from aicos.events.bus import DomainEvent
from aicos.llm.providers import LLMResponse, Message
from aicos.llm.router import ModelSpec, TaskType
from aicos.plugins.context import CapabilityDenied, PluginContext
from aicos.security.policy import ActionRequest

if TYPE_CHECKING:
    from aicos.plugins.manager import PluginRegistrar


class Plugin:
    """Base class. Override activate(); deactivate() is optional."""

    def activate(self, ctx: PluginContext, registrar: PluginRegistrar) -> Any:  # may be async
        raise NotImplementedError

    def deactivate(self) -> Any:  # may be async
        return None


__all__ = [
    "ActionRequest",
    "AgentInput",
    "AgentOutput",
    "AgentSpec",
    "CapabilityDenied",
    "DomainEvent",
    "LLMResponse",
    "Message",
    "ModelSpec",
    "Permission",
    "Plugin",
    "PluginContext",
    "PluginRegistrar",
    "ProposedAction",
    "TaskType",
]


def __getattr__(name: str) -> Any:
    if name == "PluginRegistrar":
        from aicos.plugins.manager import PluginRegistrar

        return PluginRegistrar
    raise AttributeError(name)
