"""Metrics facade. Prometheus when available; no-op otherwise (keeps core dependency-free)."""

from __future__ import annotations

from typing import Any, Protocol


class Metrics(Protocol):
    def task(self, agent: str, status: str, seconds: float) -> None: ...
    def action(self, action: str, status: str) -> None: ...
    def firewall_block(self, threat: str) -> None: ...
    def llm(self, model: str, task: str, ok: bool, tokens_in: int, tokens_out: int, cost: float, seconds: float) -> None: ...


class NoopMetrics:
    def task(self, agent: str, status: str, seconds: float) -> None: ...
    def action(self, action: str, status: str) -> None: ...
    def firewall_block(self, threat: str) -> None: ...
    def llm(self, model: str, task: str, ok: bool, tokens_in: int, tokens_out: int, cost: float, seconds: float) -> None: ...


class PrometheusMetrics:
    def __init__(self, registry: Any = None) -> None:
        from prometheus_client import CollectorRegistry, Counter, Histogram

        self.registry = registry or CollectorRegistry()
        r = self.registry
        self._tasks = Counter("aicos_tasks_total", "Tasks by agent and status", ["agent", "status"], registry=r)
        self._task_lat = Histogram(
            "aicos_task_seconds", "Task latency", ["agent"], registry=r, buckets=(0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300)
        )
        self._actions = Counter("aicos_actions_total", "Proposed actions by outcome", ["action", "status"], registry=r)
        self._fw = Counter("aicos_firewall_blocks_total", "Prompt firewall blocks", ["threat"], registry=r)
        self._llm = Counter("aicos_llm_requests_total", "LLM calls", ["model", "task", "ok"], registry=r)
        self._tokens = Counter("aicos_llm_tokens_total", "LLM tokens", ["model", "direction"], registry=r)
        self._cost = Counter("aicos_llm_cost_usd_total", "LLM cost (USD)", ["model"], registry=r)
        self._llm_lat = Histogram("aicos_llm_seconds", "LLM latency", ["model"], registry=r)

    def task(self, agent: str, status: str, seconds: float) -> None:
        self._tasks.labels(agent, status).inc()
        self._task_lat.labels(agent).observe(seconds)

    def action(self, action: str, status: str) -> None:
        self._actions.labels(action, status).inc()

    def firewall_block(self, threat: str) -> None:
        self._fw.labels(threat).inc()

    def llm(self, model: str, task: str, ok: bool, tokens_in: int, tokens_out: int, cost: float, seconds: float) -> None:
        self._llm.labels(model, task, str(ok).lower()).inc()
        self._tokens.labels(model, "in").inc(tokens_in)
        self._tokens.labels(model, "out").inc(tokens_out)
        self._cost.labels(model).inc(cost)
        self._llm_lat.labels(model).observe(seconds)
