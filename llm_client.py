"""
Minimal multi-provider LLM client interface.

Anthropic is the primary, tested backend for this project. OpenAI and Ask Sage
adapters are included to show the interface generalizes across both a direct
vendor API and a DoD/DIB-facing multi-model gateway, but neither has been run
against live credentials in this repo - treat them as reference code, not a
verified path, until someone runs them with real accounts.
"""
from __future__ import annotations

import os
from typing import Any


class AnthropicClient:
    """Tested backend - this is what every demo script in this repo actually calls."""

    def __init__(self, model: str = "claude-sonnet-4-5"):
        import anthropic

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("Set ANTHROPIC_API_KEY before running this demo.")
        self._client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    def create(self, *, system: str, messages: list[dict], max_tokens: int = 3000) -> Any:
        return self._client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=messages,
        )


class OpenAIClient:
    """
    NOT independently verified in this repo - no OpenAI/Codex key was available
    at build time. Included to show the same interface can front either provider.
    """

    def __init__(self, model: str = "gpt-5"):
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("Set OPENAI_API_KEY before running this demo.")
        import openai  # type: ignore

        self._client = openai.OpenAI(api_key=api_key)
        self.model = model

    def create(self, *, system: str, messages: list[dict], max_tokens: int = 3000) -> Any:
        oa_messages = [{"role": "system", "content": system}] + messages
        return self._client.chat.completions.create(
            model=self.model,
            max_completion_tokens=max_tokens,
            messages=oa_messages,
        )


class AskSageClient:
    """
    NOT independently verified in this repo - no Ask Sage account was available
    at build time. Included because api.asksage.ai is the actual DIB/contractor-
    facing multi-model gateway DoD IL5/IL6 GenAI work typically runs through
    (see https://github.com/Ask-Sage/AskSage-Open-Source-Community for the
    public API docs this is built from) - not a guess at an interface, the
    documented REST contract.
    """

    USER_BASE_URL = "https://api.asksage.ai/user"
    SERVER_BASE_URL = "https://api.asksage.ai/server"

    def __init__(self, model: str = "openai_gpt"):
        import requests

        self._requests = requests
        email = os.environ.get("ASKSAGE_EMAIL")
        api_key = os.environ.get("ASKSAGE_API_KEY")
        if not email or not api_key:
            raise RuntimeError("Set ASKSAGE_EMAIL and ASKSAGE_API_KEY before running this demo.")

        auth = requests.post(
            f"{self.USER_BASE_URL}/get-token-with-api-key",
            json={"email": email, "api_key": api_key},
            timeout=30,
        ).json()
        token = auth.get("access_token", api_key)
        self._headers = {"x-access-tokens": token, "Content-Type": "application/json"}
        self.model = model

    def create(self, *, system: str, messages: list[dict], max_tokens: int = 3000) -> Any:
        message = messages[-1]["content"] if messages else ""
        response = self._requests.post(
            f"{self.SERVER_BASE_URL}/query",
            headers=self._headers,
            json={
                "message": message,
                "model": self.model,
                "system_prompt": system,
                "temperature": 0.0,
                "dataset": "none",
                "live": 0,
            },
            timeout=30,
        )
        return response.json()  # {"message": "...", "references": [...], ...}


def get_client(provider: str = "anthropic"):
    if provider == "anthropic":
        return AnthropicClient()
    if provider == "openai":
        return OpenAIClient()
    if provider == "asksage":
        return AskSageClient()
    raise ValueError(f"Unknown provider: {provider}")
