"""Agent registry: catalog loading, factories, keyword routing."""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

import yaml

from aicos.agents.base import Agent, AgentSpec, Department
from aicos.agents.llm_agent import LLMAgent
from aicos.domain.errors import NotFound, ValidationFailed
from aicos.llm.router import LLMRouter

AgentFactory = Callable[[AgentSpec], Agent]


def load_catalog(directory: str | Path) -> list[AgentSpec]:
    specs: list[AgentSpec] = []
    for path in sorted(Path(directory).glob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        dept = raw.get("department")
        for item in raw.get("agents", []):
            specs.append(AgentSpec.model_validate({"department": dept, **item}))
    return specs


class AgentRegistry:
    DEFAULT_AGENT = "coo"

    def __init__(self, router: LLMRouter) -> None:
        self._router = router
        self._specs: dict[str, AgentSpec] = {}
        self._factories: dict[str, AgentFactory] = {}
        self._instances: dict[str, Agent] = {}

    def register(self, spec: AgentSpec, factory: AgentFactory | None = None, *, replace: bool = False) -> None:
        if spec.id in self._specs and not replace:
            raise ValidationFailed(f"agent '{spec.id}' already registered")
        self._specs[spec.id] = spec
        self._factories[spec.id] = factory or (lambda s: LLMAgent(s, self._router))
        self._instances.pop(spec.id, None)

    def unregister(self, agent_id: str) -> None:
        for d in (self._specs, self._factories, self._instances):
            d.pop(agent_id, None)

    def load_catalog(self, directory: str | Path) -> int:
        specs = load_catalog(directory)
        for s in specs:
            self.register(s)
        return len(specs)

    def spec(self, agent_id: str) -> AgentSpec:
        try:
            return self._specs[agent_id]
        except KeyError:
            raise NotFound(f"agent '{agent_id}' not found") from None

    def get(self, agent_id: str) -> Agent:
        if agent_id not in self._instances:
            self._instances[agent_id] = self._factories[self.spec(agent_id).id](self._specs[agent_id])
        return self._instances[agent_id]

    def list(self, department: Department | None = None) -> list[AgentSpec]:
        return sorted((s for s in self._specs.values() if department is None or s.department == department), key=lambda s: s.id)

    def route(self, objective: str) -> str:
        """Pick the agent whose keywords best match the objective (deterministic)."""
        text = objective.lower()
        best, best_score = None, 0
        for spec in self._specs.values():
            score = sum(len(re.findall(rf"\b{re.escape(k.lower())}\b", text)) for k in spec.keywords)
            if score > best_score:
                best, best_score = spec.id, score
        if best:
            return best
        return self.DEFAULT_AGENT if self.DEFAULT_AGENT in self._specs else next(iter(sorted(self._specs)), "")
