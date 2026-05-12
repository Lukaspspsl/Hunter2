"""OpenAI-compatible HTTP client for llama.cpp.

Talks to the llama.cpp server running on the RunPod pod (port 8090 by
default). Honors llm.yaml settings — base_url, model, temperature, timeout.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, AsyncIterator, Optional

import httpx

from ..config_loader import LLMConfig
from ..core.logger import get_logger

log = get_logger("llm_client")


class LLMUnavailable(RuntimeError):
    """Raised when the LLM endpoint cannot be reached and fallback is disabled."""


@dataclass
class ChatMessage:
    role: str
    content: str

    def to_dict(self) -> dict:
        return {"role": self.role, "content": self.content}


class LLMClient:
    def __init__(self, cfg: LLMConfig):
        self.cfg = cfg
        self._client = httpx.AsyncClient(timeout=cfg.timeout)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def is_available(self) -> bool:
        """Hit /v1/models for a cheap liveness probe."""
        if not self.cfg.availability_check.enabled:
            return True
        url = self.cfg.base_url.rstrip("/") + "/models"
        try:
            r = await self._client.get(
                url,
                headers={"Authorization": f"Bearer {self.cfg.api_key}"},
                timeout=5,
            )
            return r.status_code < 500
        except Exception as e:
            log.warning(f"LLM availability check failed: {e}")
            return False

    async def chat(
        self,
        messages: list[ChatMessage],
        *,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        stop: Optional[list[str]] = None,
    ) -> str:
        """Single-shot chat completion. Returns assistant text."""
        url = self.cfg.base_url.rstrip("/") + "/chat/completions"
        payload: dict[str, Any] = {
            "model": self.cfg.model,
            "messages": [m.to_dict() for m in messages],
            "temperature": temperature if temperature is not None else self.cfg.temperature,
        }
        if max_tokens:
            payload["max_tokens"] = max_tokens
        if stop:
            payload["stop"] = stop

        try:
            r = await self._client.post(
                url,
                json=payload,
                headers={"Authorization": f"Bearer {self.cfg.api_key}"},
            )
        except httpx.HTTPError as e:
            raise LLMUnavailable(f"LLM request failed: {e}") from e

        if r.status_code >= 400:
            raise LLMUnavailable(f"LLM HTTP {r.status_code}: {r.text[:200]}")

        body = r.json()
        choice = (body.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        return msg.get("content", "")

    async def chat_stream(
        self,
        messages: list[ChatMessage],
        *,
        temperature: Optional[float] = None,
    ) -> AsyncIterator[str]:
        """Stream chunks for REPL UX. Yields incremental content strings."""
        url = self.cfg.base_url.rstrip("/") + "/chat/completions"
        payload = {
            "model": self.cfg.model,
            "messages": [m.to_dict() for m in messages],
            "temperature": temperature if temperature is not None else self.cfg.temperature,
            "stream": True,
        }
        async with self._client.stream(
            "POST",
            url,
            json=payload,
            headers={"Authorization": f"Bearer {self.cfg.api_key}"},
        ) as r:
            if r.status_code >= 400:
                raise LLMUnavailable(f"LLM HTTP {r.status_code}")
            async for line in r.aiter_lines():
                if not line or not line.startswith("data:"):
                    continue
                data = line.removeprefix("data:").strip()
                if data == "[DONE]":
                    return
                try:
                    import json as _json
                    chunk = _json.loads(data)
                except Exception:
                    continue
                delta = (chunk.get("choices") or [{}])[0].get("delta", {})
                content = delta.get("content")
                if content:
                    yield content
