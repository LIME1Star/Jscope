"""AI providers. Deliberately tiny: one method, text in -> text out. Nothing here knows about findings."""

from __future__ import annotations

import os
from typing import Protocol


class AIError(Exception):
    pass


class AIProvider(Protocol):
    name: str

    def complete(self, system: str, user: str, max_tokens: int) -> str: ...


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str = "claude-sonnet-5-5", api_key: str | None = None,
                 api_key_env: str = "ANTHROPIC_API_KEY", base_url: str = "https://api.anthropic.com",
                 timeout: int = 60):
        self.model = model
        self.api_key = api_key or os.environ.get(api_key_env)
        self.api_key_env = api_key_env
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def complete(self, system: str, user: str, max_tokens: int) -> str:
        if not self.api_key:
            raise AIError(f"no API key: set ${self.api_key_env}")
        import requests
        try:
            r = requests.post(
                f"{self.base_url}/v1/messages",
                headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                json={"model": self.model, "max_tokens": max_tokens, "system": system,
                      "messages": [{"role": "user", "content": user}]},
                timeout=self.timeout)
        except requests.RequestException as exc:
            raise AIError(f"request failed: {exc}") from exc
        if r.status_code != 200:
            raise AIError(f"provider returned HTTP {r.status_code}")        # body deliberately not echoed
        try:
            return "".join(b.get("text", "") for b in r.json()["content"] if b.get("type") == "text")
        except (KeyError, ValueError, TypeError) as exc:
            raise AIError("unexpected provider response shape") from exc


class StaticProvider:
    """Returns a fixed string. For tests and offline demos; never touches the network."""
    name = "static"

    def __init__(self, reply: str):
        self.reply = reply
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str, max_tokens: int) -> str:
        self.calls.append((system, user))
        return self.reply


def get_provider(cfg: dict) -> AIProvider:
    kind = (cfg.get("provider") or "anthropic").lower()
    if kind == "anthropic":
        return AnthropicProvider(model=cfg.get("model", "claude-sonnet-5-5"),
                                 api_key_env=cfg.get("api_key_env", "ANTHROPIC_API_KEY"))
    raise AIError(f"unknown AI provider {kind!r} (supported: anthropic)")
