"""
LLM-based diagnostic agent using Claude API.

Addresses key design requirements:
1. Diff-aware prompts — uses SnapshotDiff to show what changed
2. Full few-shot coverage — 8 examples covering all fault classes + edge cases
3. Artifact logging — tracks prompt hash, model, tokens, latency per invocation
4. Multi-model support — model configurable via constructor or env var
"""

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import anthropic

import sys
sys.path.insert(0, str(__file__).rsplit('/', 2)[0])

from telemetry.schemas import DiagnosisResult, NetworkSnapshot
from telemetry.snapshot import SnapshotDiff

from .base import BaseDiagnosticEngine, no_fault_result

logger = logging.getLogger(__name__)

# Model defaults — configurable via env var or constructor
DEFAULT_MODEL = os.environ.get("LLM_MODEL", "claude-sonnet-4-5-20250929")

# Paths to prompt files
PROMPTS_DIR = Path(__file__).parent / "prompts"
SYSTEM_PROMPT_FILE = PROMPTS_DIR / "system_prompt.txt"
FEW_SHOT_FILE = PROMPTS_DIR / "few_shot_examples.json"


class LLMAgent(BaseDiagnosticEngine):
    """
    LLM-based diagnostic agent using Anthropic Claude.

    Uses diff-aware, chain-of-thought prompting with few-shot examples
    covering all fault classes and ambiguous edge cases.
    """

    def __init__(
        self,
        model: str = None,
        api_key: Optional[str] = None,
        max_retries: int = 3,
        temperature: float = 0.0,
    ):
        super().__init__(name="llm-agent")
        self.model = model or DEFAULT_MODEL
        self.max_retries = max_retries
        self.temperature = temperature

        # Token tracking
        self._total_input_tokens = 0
        self._total_output_tokens = 0
        self._invocation_count = 0

        # Initialize Anthropic client
        api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(
                "Anthropic API key required. Set ANTHROPIC_API_KEY environment variable "
                "or pass api_key parameter."
            )
        self.client = anthropic.Anthropic(api_key=api_key)

        # Load prompts
        self.system_prompt = self._load_system_prompt()
        self.few_shot_examples = self._load_few_shot_examples()
        self.prompt_hash = self._compute_prompt_hash()

    # ------------------------------------------------------------------
    # Prompt loading
    # ------------------------------------------------------------------

    def _load_system_prompt(self) -> str:
        try:
            with open(SYSTEM_PROMPT_FILE, "r") as f:
                return f.read()
        except FileNotFoundError:
            logger.warning(f"System prompt file not found: {SYSTEM_PROMPT_FILE}")
            return self._default_system_prompt()

    def _load_few_shot_examples(self) -> list[dict]:
        try:
            with open(FEW_SHOT_FILE, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Few-shot examples file not found: {FEW_SHOT_FILE}")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse few-shot examples: {e}")
            return []

    def _default_system_prompt(self) -> str:
        return """You are a network fault diagnosis expert. Analyze OSPF network telemetry
and identify faults. Respond with valid JSON containing:
- fault_detected: boolean
- fault_class: link_failure|flapping_link|stale_route|missing_route|counter_anomaly|none
- location: affected component
- confidence: 0.0-1.0
- reasoning: step-by-step analysis
- remediation: suggested fix"""

    def _compute_prompt_hash(self) -> str:
        hasher = hashlib.sha256()
        hasher.update(self.system_prompt.encode("utf-8"))
        hasher.update(json.dumps(self.few_shot_examples, sort_keys=True).encode("utf-8"))
        return hasher.hexdigest()[:16]

    # ------------------------------------------------------------------
    # Snapshot encoding + diff computation
    # ------------------------------------------------------------------

    def _encode_snapshot(self, snapshot: NetworkSnapshot) -> str:
        encoded = {
            "snapshot_id": snapshot.snapshot_id,
            "timestamp": snapshot.timestamp.isoformat(),
            "routers": {}
        }

        for router_name, telemetry in snapshot.routers.items():
            router_data = {
                "router_name": telemetry.router_name,
                "router_id": telemetry.router_id,
                "neighbors": [],
                "interfaces": {},
                "routing_table": {"routes": {}},
                "lsdb": {"router_lsas": []}
            }

            for neighbor in telemetry.neighbors:
                nd = {
                    "neighbor_id": neighbor.neighbor_id,
                    "state": neighbor.state,
                    "interface": neighbor.interface,
                }
                if neighbor.retransmit_counter > 0:
                    nd["retransmit_counter"] = neighbor.retransmit_counter
                router_data["neighbors"].append(nd)

            for iface_name, interface in telemetry.interfaces.items():
                router_data["interfaces"][iface_name] = {
                    "name": interface.name,
                    "link_status": interface.link_status,
                    "counters": {
                        "error_rate": round(interface.counters.error_rate, 2),
                        "drop_rate": round(interface.counters.drop_rate, 2),
                    }
                }

            for prefix, routes in telemetry.routing_table.routes.items():
                router_data["routing_table"]["routes"][prefix] = [
                    {
                        "prefix": route.prefix,
                        "prefix_len": route.prefix_len,
                        "protocol": route.protocol,
                        "distance": route.distance,
                        "nexthops": [
                            {"ip": nh.ip, "interface": nh.interface}
                            for nh in route.nexthops
                        ]
                    }
                    for route in routes
                ]

            for lsa in telemetry.lsdb.router_lsas:
                router_data["lsdb"]["router_lsas"].append({
                    "lsa_id": lsa.lsa_id,
                    "advertising_router": lsa.advertising_router,
                    "link_count": lsa.link_count,
                    "sequence_number": lsa.sequence_number,
                })

            encoded["routers"][router_name] = router_data

        return json.dumps(encoded, indent=2)

    def _compute_snapshot_diff(
        self,
        previous: NetworkSnapshot,
        current: NetworkSnapshot,
    ) -> Optional[str]:
        """
        Compute a structured diff between previous and current snapshots.

        Returns JSON string of only the changes, or None if no changes.
        """
        diff = SnapshotDiff(previous, current)
        diff_data = diff.compute()

        # Only include if there are actual changes
        if not diff.has_changes:
            return None

        # Build a concise diff summary for the prompt
        summary = {
            "time_delta_ms": diff_data["time_delta_ms"],
            "routers_added": diff_data["routers_added"],
            "routers_removed": diff_data["routers_removed"],
            "changes_per_router": {},
        }

        for router, rdiff in diff_data.get("router_diffs", {}).items():
            changes = {}
            for key in ("neighbor_changes", "lsdb_changes", "route_changes", "interface_changes"):
                if rdiff.get(key):
                    changes[key] = rdiff[key]
            if changes:
                summary["changes_per_router"][router] = changes

        if not summary["changes_per_router"] and not summary["routers_added"] and not summary["routers_removed"]:
            return None

        return json.dumps(summary, indent=2)

    # ------------------------------------------------------------------
    # Message construction
    # ------------------------------------------------------------------

    def _build_messages(
        self,
        snapshot_json: str,
        diff_json: Optional[str] = None,
    ) -> list[dict]:
        messages = []

        # Few-shot examples
        for example in self.few_shot_examples:
            messages.append({
                "role": "user",
                "content": f"Analyze this network snapshot:\n\n```json\n{json.dumps(example['input'], indent=2)}\n```"
            })
            messages.append({
                "role": "assistant",
                "content": f"```json\n{json.dumps(example['output'], indent=2)}\n```"
            })

        # Actual query — with diff if available
        user_content = f"Analyze this network snapshot and diagnose any faults:\n\n```json\n{snapshot_json}\n```"

        if diff_json:
            user_content += f"\n\nChanges from previous snapshot:\n\n```json\n{diff_json}\n```"

        messages.append({"role": "user", "content": user_content})
        return messages

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_response(self, response_text: str) -> dict:
        if "```json" in response_text:
            start = response_text.find("```json") + 7
            end = response_text.find("```", start)
            if end > start:
                response_text = response_text[start:end]
        elif "```" in response_text:
            start = response_text.find("```") + 3
            end = response_text.find("```", start)
            if end > start:
                response_text = response_text[start:end]

        return json.loads(response_text.strip())

    def _response_to_diagnosis(
        self,
        response_data: dict,
        artifact: Optional[dict] = None,
    ) -> DiagnosisResult:
        # Build raw_output with both response and artifact metadata
        raw = {"response": response_data}
        if artifact:
            raw["artifact"] = artifact

        return DiagnosisResult(
            fault_detected=response_data.get("fault_detected", False),
            fault_class=(
                response_data.get("fault_class")
                if response_data.get("fault_class") != "none" else None
            ),
            location=response_data.get("location"),
            affected_routers=response_data.get("affected_routers", []),
            affected_interfaces=response_data.get("affected_interfaces", []),
            affected_prefixes=response_data.get("affected_prefixes", []),
            confidence=response_data.get("confidence", 0.0),
            reasoning=response_data.get("reasoning", ""),
            remediation=response_data.get("remediation"),
            raw_output=json.dumps(raw),
        )

    # ------------------------------------------------------------------
    # Artifact logging
    # ------------------------------------------------------------------

    def _log_artifact(
        self,
        snapshot_id: str,
        input_tokens: int,
        output_tokens: int,
        attempt: int,
        latency_ms: int,
        stop_reason: str,
    ) -> dict:
        artifact = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "snapshot_id": snapshot_id,
            "model": self.model,
            "prompt_hash": self.prompt_hash,
            "temperature": self.temperature,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "attempt": attempt,
            "latency_ms": latency_ms,
            "stop_reason": stop_reason,
        }

        logger.info("LLM_ARTIFACT: %s", json.dumps(artifact))
        return artifact

    # ------------------------------------------------------------------
    # Diagnosis
    # ------------------------------------------------------------------

    def diagnose(
        self,
        snapshot: NetworkSnapshot,
        previous_snapshot: Optional[NetworkSnapshot] = None,
    ) -> DiagnosisResult:
        start_time = time.time()
        self._invocation_count += 1

        # Encode current snapshot
        snapshot_json = self._encode_snapshot(snapshot)

        # Compute diff if previous snapshot available
        diff_json = None
        if previous_snapshot is not None:
            diff_json = self._compute_snapshot_diff(previous_snapshot, snapshot)

        # Build messages
        messages = self._build_messages(snapshot_json, diff_json)

        # Try with retries for JSON parsing
        last_error = None
        for attempt in range(self.max_retries):
            try:
                attempt_start = time.time()

                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=2048,
                    temperature=self.temperature,
                    system=self.system_prompt,
                    messages=messages,
                )

                attempt_ms = int((time.time() - attempt_start) * 1000)
                response_text = response.content[0].text

                # Track tokens
                input_tokens = getattr(response.usage, "input_tokens", 0)
                output_tokens = getattr(response.usage, "output_tokens", 0)
                stop_reason = getattr(response, "stop_reason", "unknown")

                self._total_input_tokens += input_tokens
                self._total_output_tokens += output_tokens

                # Log artifact
                artifact = self._log_artifact(
                    snapshot_id=snapshot.snapshot_id,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    attempt=attempt + 1,
                    latency_ms=attempt_ms,
                    stop_reason=stop_reason,
                )

                # Parse JSON
                response_data = self._parse_response(response_text)

                result = self._response_to_diagnosis(response_data, artifact)
                result.diagnosis_time_ms = int((time.time() - start_time) * 1000)

                logger.info(
                    f"LLM diagnosis completed in {result.diagnosis_time_ms}ms "
                    f"(attempt {attempt + 1}, {input_tokens}+{output_tokens} tokens)"
                )

                return result

            except json.JSONDecodeError as e:
                last_error = e
                logger.warning(f"JSON parse error on attempt {attempt + 1}: {e}")
                if attempt < self.max_retries - 1:
                    messages.append({
                        "role": "assistant",
                        "content": response_text if 'response_text' in locals() else ""
                    })
                    messages.append({
                        "role": "user",
                        "content": "Your response was not valid JSON. Please respond with ONLY a valid JSON object, no other text."
                    })

            except anthropic.APIError as e:
                logger.error(f"Anthropic API error: {e}")
                last_error = e
                break

            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                last_error = e
                break

        logger.error(f"LLM diagnosis failed after {self.max_retries} attempts: {last_error}")
        return DiagnosisResult(
            fault_detected=False,
            fault_class=None,
            confidence=0.0,
            reasoning=f"LLM diagnosis failed: {last_error}",
            diagnosis_time_ms=int((time.time() - start_time) * 1000),
        )

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        stats = super().get_stats()
        stats.update({
            "model": self.model,
            "temperature": self.temperature,
            "max_retries": self.max_retries,
            "num_few_shot_examples": len(self.few_shot_examples),
            "prompt_hash": self.prompt_hash,
            "total_input_tokens": self._total_input_tokens,
            "total_output_tokens": self._total_output_tokens,
            "invocation_count": self._invocation_count,
        })
        return stats


class MockLLMAgent(BaseDiagnosticEngine):
    """
    Mock LLM agent for testing without API calls.

    Returns predefined responses based on simple pattern matching.
    """

    def __init__(self):
        super().__init__(name="mock-llm-agent")
        self.prompt_hash = "mock"
        self._total_input_tokens = 0
        self._total_output_tokens = 0

    def diagnose(
        self,
        snapshot: NetworkSnapshot,
        previous_snapshot: Optional[NetworkSnapshot] = None,
    ) -> DiagnosisResult:
        start_time = time.time()

        for router_name, telemetry in snapshot.routers.items():
            for iface_name, interface in telemetry.interfaces.items():
                if interface.link_status.lower() == "down":
                    return DiagnosisResult(
                        fault_detected=True,
                        fault_class="link_failure",
                        location=f"{router_name}:{iface_name}",
                        affected_routers=[router_name],
                        affected_interfaces=[f"{router_name}:{iface_name}"],
                        confidence=0.90,
                        reasoning="[MOCK] Interface is down",
                        diagnosis_time_ms=int((time.time() - start_time) * 1000),
                    )

            for neighbor in telemetry.non_full_adjacencies:
                return DiagnosisResult(
                    fault_detected=True,
                    fault_class="link_failure",
                    location=f"{router_name}:{neighbor.interface}",
                    affected_routers=[router_name],
                    confidence=0.80,
                    reasoning=f"[MOCK] Neighbor {neighbor.neighbor_id} not Full",
                    diagnosis_time_ms=int((time.time() - start_time) * 1000),
                )

            for iface_name, interface in telemetry.interfaces.items():
                if interface.counters.error_rate > 1.0 or interface.counters.drop_rate > 1.0:
                    return DiagnosisResult(
                        fault_detected=True,
                        fault_class="counter_anomaly",
                        location=f"{router_name}:{iface_name}",
                        affected_routers=[router_name],
                        confidence=0.75,
                        reasoning="[MOCK] High error/drop rate",
                        diagnosis_time_ms=int((time.time() - start_time) * 1000),
                    )

        return no_fault_result("[MOCK] No faults detected")

    def get_stats(self) -> dict:
        stats = super().get_stats()
        stats.update({
            "model": "mock-llm",
            "temperature": 0.0,
            "max_retries": 0,
            "num_few_shot_examples": 0,
            "prompt_hash": self.prompt_hash,
            "total_input_tokens": 0,
            "total_output_tokens": 0,
        })
        return stats
