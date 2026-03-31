"""
Config planners that propose patches/fixed configs.

Includes:
- ConfigPlan dataclass
- Mock planner (uses known fixed configs from scenarios)
- LLM planner stub that can call Anthropic when configured
"""

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

try:
    import anthropic
except Exception:  # pragma: no cover - optional if Anthropic not installed
    anthropic = None

from .intent import Intent
from .validator import ValidationError

logger = logging.getLogger(__name__)


@dataclass
class ConfigPlan:
    patched_config: str
    reasoning: str
    patch_text: Optional[str] = None
    raw_response: Optional[str] = None


class ConfigPlanner:
    """Base planner interface."""

    def plan(
        self,
        config_text: str,
        intent: Intent,
        errors: List[ValidationError]
    ) -> ConfigPlan:
        raise NotImplementedError


class MockConfigPlanner(ConfigPlanner):
    """
    Mock planner that returns a known-good config from a provided file.

    Useful for tests and offline runs.
    """

    def __init__(self, fixed_config_path: Path):
        self.fixed_config_path = fixed_config_path

    def plan(
        self,
        config_text: str,
        intent: Intent,
        errors: List[ValidationError]
    ) -> ConfigPlan:
        patched = self.fixed_config_path.read_text()
        return ConfigPlan(
            patched_config=patched,
            reasoning="Applied known-good fixture config (mock planner).",
            patch_text=None,
            raw_response=None,
        )


class LLMConfigPlanner(ConfigPlanner):
    """
    LLM-backed planner that asks Claude to propose a patch.

    Expects ANTHROPIC_API_KEY to be set; otherwise raises ValueError.
    """

    SYSTEM_PROMPT = """You are a network automation assistant. Given a FRR/OSPF config,
its intent, and validation errors, propose a corrected configuration.
Respond with JSON: {"patched_config": "<full config>", "reasoning": "<brief>"}.
Do not include any text outside the JSON. Keep the config minimal and only change what is necessary."""

    def __init__(
        self,
        model: str = "claude-sonnet-4-5-20250929",
        temperature: float = 0.0,
    ):
        if anthropic is None:
            raise ValueError("Anthropic SDK not installed; cannot use LLM planner.")
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY not set; cannot use LLM planner.")
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model
        self.temperature = temperature

    def plan(
        self,
        config_text: str,
        intent: Intent,
        errors: List[ValidationError]
    ) -> ConfigPlan:
        intent_payload = json.dumps(intent, default=lambda o: o.__dict__, indent=2)
        errors_payload = json.dumps([e.__dict__ for e in errors], indent=2)

        user_prompt = (
            "Current config:\n```\n"
            f"{config_text}\n```\n\n"
            "Intent:\n```\n"
            f"{intent_payload}\n```\n\n"
            "Validation errors:\n```\n"
            f"{errors_payload}\n```\n\n"
            "Return ONLY JSON with patched_config and reasoning."
        )

        response = self.client.messages.create(
            model=self.model,
            max_tokens=2048,
            temperature=self.temperature,
            system=self.SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )

        text = response.content[0].text
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            logger.error("LLM response was not valid JSON")
            raise

        patched_config = data.get("patched_config", "")
        reasoning = data.get("reasoning", "")
        patch_text = data.get("patch_text")

        return ConfigPlan(
            patched_config=patched_config,
            reasoning=reasoning,
            patch_text=patch_text,
            raw_response=text,
        )
