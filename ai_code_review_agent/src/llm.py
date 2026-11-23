"""Thin optional wrapper around the Anthropic API. Agents fall back to rules if unavailable."""
import json
import re
from . import config


class LLM:
    def __init__(self):
        self.client = None
        if config.ANTHROPIC_API_KEY:
            try:
                import anthropic
                self.client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)
            except Exception:
                self.client = None

    @property
    def available(self) -> bool:
        return self.client is not None

    def complete(self, system: str, prompt: str, max_tokens: int = 900) -> str:
        msg = self.client.messages.create(
            model=config.CLAUDE_MODEL, max_tokens=max_tokens, system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")

    def complete_json(self, system: str, prompt: str, max_tokens: int = 900) -> dict:
        text = self.complete(system + "\nRespond with ONLY a JSON object.", prompt, max_tokens)
        text = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M).strip()
        return json.loads(text)
