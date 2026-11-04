"""LLM provider protocol. Concrete adapters live in aicos.infrastructure (Ollama, vLLM, OpenAI-compatible)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal, Protocol

from pydantic import BaseModel


class Message(BaseModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str


class LLMResponse(BaseModel):
    text: str
    model: str
    provider: str
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: float = 0.0
    cost_usd: float = 0.0


class LLMProvider(Protocol):
    name: str

    async def generate(
        self,
        model: str,
        messages: list[Message],
        *,
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> LLMResponse: ...


class ProviderUnavailable(RuntimeError):
    pass


class EchoProvider:
    """Deterministic offline provider for tests, CI and demo mode."""

    name = "echo"

    def __init__(self, responder: Callable[[str, list[Message]], str] | None = None, fail_models: set[str] | None = None) -> None:
        self._responder = responder
        self.fail_models = fail_models or set()
        self.calls: list[tuple[str, list[Message]]] = []

    async def generate(
        self,
        model: str,
        messages: list[Message],
        *,
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        self.calls.append((model, messages))
        if model in self.fail_models:
            raise ProviderUnavailable(f"{model} unavailable")
        user = next((m.content for m in reversed(messages) if m.role == "user"), "")
        text = self._responder(model, messages) if self._responder else f"[{model}] {user[:400]}"
        return LLMResponse(
            text=text,
            model=model,
            provider=self.name,
            input_tokens=sum(len(m.content) // 4 for m in messages),
            output_tokens=len(text) // 4,
        )
