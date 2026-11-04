"""LLM Router: task-aware model selection, constraints, fallback chains, circuit breaking.

Routing table (defaults, override via models/registry.yaml):
  coding     -> deepseek-coder-v2, qwen3-coder, qwen3
  reasoning  -> deepseek-r1, qwen3
  business   -> qwen3, llama3.1
  fast       -> mistral, gemma3
  general    -> qwen3, llama3.1, mistral
  embedding  -> bge-m3, nomic-embed-text, jina-embeddings-v2
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from aicos.llm.providers import LLMProvider, LLMResponse, Message


class TaskType(StrEnum):
    CODING = "coding"
    REASONING = "reasoning"
    BUSINESS = "business"
    FAST = "fast"
    GENERAL = "general"
    EMBEDDING = "embedding"


class ModelSpec(BaseModel):
    name: str
    provider: str = "ollama"
    tasks: list[TaskType]
    context_window: int = 32_768
    local: bool = True
    cost_per_1k_input: float = 0.0
    cost_per_1k_output: float = 0.0
    quality: int = Field(default=5, ge=1, le=10)


DEFAULT_MODELS: list[ModelSpec] = [
    ModelSpec(name="deepseek-coder-v2:16b", tasks=[TaskType.CODING], context_window=131_072, quality=8),
    ModelSpec(name="qwen3-coder:30b", tasks=[TaskType.CODING], context_window=262_144, quality=9),
    ModelSpec(name="deepseek-r1:14b", tasks=[TaskType.REASONING, TaskType.CODING], context_window=131_072, quality=8),
    ModelSpec(
        name="qwen3:14b", tasks=[TaskType.BUSINESS, TaskType.GENERAL, TaskType.REASONING, TaskType.CODING], context_window=40_960, quality=8
    ),
    ModelSpec(name="llama3.1:8b", tasks=[TaskType.GENERAL, TaskType.BUSINESS], context_window=131_072, quality=6),
    ModelSpec(name="mistral:7b", tasks=[TaskType.FAST, TaskType.GENERAL], context_window=32_768, quality=5),
    ModelSpec(name="gemma3:4b", tasks=[TaskType.FAST], context_window=131_072, quality=4),
    ModelSpec(name="bge-m3", tasks=[TaskType.EMBEDDING], context_window=8_192),
    ModelSpec(name="nomic-embed-text", tasks=[TaskType.EMBEDDING], context_window=8_192),
    ModelSpec(name="jina/jina-embeddings-v2-base-en", tasks=[TaskType.EMBEDDING], context_window=8_192),
]

DEFAULT_ROUTES: dict[TaskType, list[str]] = {
    TaskType.CODING: ["deepseek-coder-v2:16b", "qwen3-coder:30b", "qwen3:14b"],
    TaskType.REASONING: ["deepseek-r1:14b", "qwen3:14b"],
    TaskType.BUSINESS: ["qwen3:14b", "llama3.1:8b"],
    TaskType.FAST: ["mistral:7b", "gemma3:4b"],
    TaskType.GENERAL: ["qwen3:14b", "llama3.1:8b", "mistral:7b"],
    TaskType.EMBEDDING: ["bge-m3", "nomic-embed-text", "jina/jina-embeddings-v2-base-en"],
}

_CLASSIFIER: list[tuple[TaskType, re.Pattern[str]]] = [
    (
        TaskType.CODING,
        re.compile(
            r"\b(code|function|bug|refactor|test|python|typescript|api|endpoint|stack ?trace|compile|regex|sql|dockerfile|pull request|unit test)\b",
            re.I,
        ),
    ),
    (
        TaskType.REASONING,
        re.compile(r"\b(why|prove|analy[sz]e|root cause|trade-?offs?|plan|strategy|architecture|evaluate|reason)\b", re.I),
    ),
    (TaskType.BUSINESS, re.compile(r"\b(sales|lead|marketing|customer|revenue|pricing|proposal|campaign|seo|crm|invoice|market)\b", re.I)),
]


def classify_task(text: str) -> TaskType:
    if len(text) < 60 and not any(rx.search(text) for _, rx in _CLASSIFIER):
        return TaskType.FAST
    for task, rx in _CLASSIFIER:
        if rx.search(text):
            return task
    return TaskType.GENERAL


class RouteConstraints(BaseModel):
    require_local: bool = True  # default: data never leaves the cluster
    max_cost_per_1k: float | None = None
    min_context: int = 0
    min_quality: int = 1


class CircuitBreaker:
    def __init__(self, threshold: int = 3, cooldown_s: float = 30.0, clock: Callable[[], float] = time.monotonic) -> None:
        self.threshold, self.cooldown, self._clock = threshold, cooldown_s, clock
        self._failures: dict[str, int] = {}
        self._open_until: dict[str, float] = {}

    def available(self, key: str) -> bool:
        return self._clock() >= self._open_until.get(key, 0.0)

    def success(self, key: str) -> None:
        self._failures[key] = 0
        self._open_until.pop(key, None)

    def failure(self, key: str) -> None:
        self._failures[key] = self._failures.get(key, 0) + 1
        if self._failures[key] >= self.threshold:
            self._open_until[key] = self._clock() + self.cooldown
            self._failures[key] = 0


class NoModelAvailable(RuntimeError):
    pass


UsageHook = Callable[[TaskType, LLMResponse | None, str, Exception | None], None]


class LLMRouter:
    def __init__(
        self,
        providers: dict[str, LLMProvider],
        models: list[ModelSpec] | None = None,
        routes: dict[TaskType, list[str]] | None = None,
        breaker: CircuitBreaker | None = None,
        usage_hook: UsageHook | None = None,
    ) -> None:
        self.providers = providers
        self.models = {m.name: m for m in (models or DEFAULT_MODELS)}
        self.routes = routes or DEFAULT_ROUTES
        self.breaker = breaker or CircuitBreaker()
        self._usage = usage_hook

    @classmethod
    def from_yaml(cls, path: str | Path, providers: dict[str, LLMProvider], **kw: object) -> LLMRouter:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        models = [ModelSpec.model_validate(m) for m in raw["models"]]
        routes = {TaskType(k): v for k, v in raw["routes"].items()}
        return cls(providers, models, routes, **kw)  # type: ignore[arg-type]

    def register_model(self, spec: ModelSpec, *, route_for: list[TaskType] | None = None, prepend: bool = False) -> None:
        """Pluggable models: plugins call this through the registrar."""
        self.models[spec.name] = spec
        for task in route_for or spec.tasks:
            chain = self.routes.setdefault(task, [])
            if spec.name not in chain:
                chain.insert(0, spec.name) if prepend else chain.append(spec.name)

    def candidates(self, task: TaskType, constraints: RouteConstraints | None = None) -> list[ModelSpec]:
        c = constraints or RouteConstraints()
        out: list[ModelSpec] = []
        for name in self.routes.get(task, []) + self.routes.get(TaskType.GENERAL, []) * (task is not TaskType.EMBEDDING):
            m = self.models.get(name)
            if m is None or m in out or m.provider not in self.providers:
                continue
            if c.require_local and not m.local:
                continue
            if c.max_cost_per_1k is not None and max(m.cost_per_1k_input, m.cost_per_1k_output) > c.max_cost_per_1k:
                continue
            if m.context_window < c.min_context or m.quality < c.min_quality:
                continue
            if not self.breaker.available(m.name):
                continue
            out.append(m)
        return out

    async def complete(
        self,
        task: TaskType,
        messages: list[Message],
        *,
        constraints: RouteConstraints | None = None,
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        if task is TaskType.EMBEDDING:
            raise ValueError("use an Embedder for embedding tasks")
        candidates = self.candidates(task, constraints)
        if not candidates:
            raise NoModelAvailable(f"no model satisfies constraints for {task}")
        last: Exception | None = None
        for m in candidates:
            started = time.perf_counter()
            try:
                resp = await self.providers[m.provider].generate(m.name, messages, temperature=temperature, max_tokens=max_tokens)
            except Exception as exc:  # noqa: BLE001 - fall through to next candidate
                self.breaker.failure(m.name)
                last = exc
                if self._usage:
                    self._usage(task, None, m.name, exc)
                continue
            self.breaker.success(m.name)
            resp.latency_ms = resp.latency_ms or (time.perf_counter() - started) * 1000
            resp.cost_usd = (resp.input_tokens * m.cost_per_1k_input + resp.output_tokens * m.cost_per_1k_output) / 1000
            if self._usage:
                self._usage(task, resp, m.name, None)
            return resp
        raise NoModelAvailable(f"all candidates failed for {task}: {last}")
