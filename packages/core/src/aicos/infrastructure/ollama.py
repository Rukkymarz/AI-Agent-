"""Ollama adapters (chat + embeddings). Works with any Ollama-served model: Qwen3, DeepSeek, Llama, Mistral, Gemma, BGE, Nomic, Jina."""

from __future__ import annotations

import time

import httpx

from aicos.llm.providers import LLMResponse, Message, ProviderUnavailable


class OllamaProvider:
    name = "ollama"

    def __init__(self, base_url: str, timeout: float = 300.0) -> None:
        self._client = httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=timeout)

    async def generate(self, model: str, messages: list[Message], *, temperature: float = 0.2, max_tokens: int = 2048) -> LLMResponse:
        started = time.perf_counter()
        try:
            r = await self._client.post(
                "/api/chat",
                json={
                    "model": model,
                    "stream": False,
                    "messages": [m.model_dump() for m in messages],
                    "options": {"temperature": temperature, "num_predict": max_tokens},
                },
            )
            r.raise_for_status()
        except httpx.HTTPError as exc:
            raise ProviderUnavailable(f"ollama {model}: {exc}") from exc
        data = r.json()
        text = data.get("message", {}).get("content", "")
        # DeepSeek-R1 / Qwen3 emit <think> blocks; keep reasoning out of user-facing output.
        if "</think>" in text:
            text = text.split("</think>", 1)[1].strip()
        return LLMResponse(
            text=text,
            model=model,
            provider=self.name,
            input_tokens=data.get("prompt_eval_count", 0),
            output_tokens=data.get("eval_count", 0),
            latency_ms=(time.perf_counter() - started) * 1000,
        )


class OllamaEmbedder:
    def __init__(self, base_url: str, model: str = "bge-m3", dim: int = 1024, timeout: float = 120.0) -> None:
        self._client = httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=timeout)
        self._model, self._dim = model, dim

    @property
    def dim(self) -> int:
        return self._dim

    @property
    def model(self) -> str:
        return self._model

    async def embed(self, texts: list[str]) -> list[list[float]]:
        out: list[list[float]] = []
        for i in range(0, len(texts), 32):
            r = await self._client.post("/api/embed", json={"model": self._model, "input": texts[i : i + 32]})
            r.raise_for_status()
            vecs = r.json()["embeddings"]
            if vecs and len(vecs[0]) != self._dim:
                raise ValueError(f"embedding dim mismatch: got {len(vecs[0])}, expected {self._dim}")
            out.extend(vecs)
        return out
