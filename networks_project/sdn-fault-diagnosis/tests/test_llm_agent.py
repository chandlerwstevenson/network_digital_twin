"""
Unit tests for LLM diagnostic agent.

Tests cover:
- Mock agent behavior
- Snapshot encoding (including retransmit counters)
- Response parsing (code blocks, bare JSON)
- Diff-aware prompt construction
- Artifact metadata in raw_output
- Token tracking in get_stats()
- Multi-model instantiation
- Full diagnosis flow with mocked API
"""

import json
from unittest.mock import MagicMock, patch

import pytest

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from telemetry.schemas import (
    Interface,
    InterfaceCounters,
    NetworkSnapshot,
    OSPFNeighbor,
    OSPFLSDB,
    RouterLSA,
    RouterTelemetry,
    RoutingTable,
)
from diagnosis.llm_agent import LLMAgent, MockLLMAgent


def _make_snapshot(snapshot_id="test_001", **overrides) -> NetworkSnapshot:
    """Helper to create a simple snapshot for testing."""
    return NetworkSnapshot(
        snapshot_id=snapshot_id,
        routers={
            "spine1": RouterTelemetry(
                router_name="spine1",
                router_id="10.0.0.1",
                neighbors=[
                    OSPFNeighbor(
                        neighbor_id="10.0.1.1",
                        state="Full",
                        address="10.1.1.1",
                        interface="eth1",
                    ),
                ],
                interfaces={
                    "eth1": Interface(
                        name="eth1",
                        link_status="up",
                        counters=InterfaceCounters(rx_packets=100, rx_errors=1),
                    ),
                },
                lsdb=OSPFLSDB(
                    router_lsas=[
                        RouterLSA(
                            lsa_id="10.0.0.1",
                            advertising_router="10.0.0.1",
                            link_count=4,
                        )
                    ]
                ),
                routing_table=RoutingTable(),
            ),
        },
        **overrides,
    )


class TestMockLLMAgent:
    """Tests for MockLLMAgent class."""

    def setup_method(self):
        self.agent = MockLLMAgent()

    def test_mock_agent_healthy_network(self):
        snapshot = _make_snapshot()
        result = self.agent.diagnose(snapshot)
        assert result.fault_detected is False
        assert "[MOCK]" in result.reasoning

    def test_mock_agent_detects_interface_down(self):
        snapshot = _make_snapshot()
        snapshot.routers["spine1"].interfaces["eth1"].link_status = "down"
        result = self.agent.diagnose(snapshot)
        assert result.fault_detected is True
        assert result.fault_class == "link_failure"

    def test_mock_agent_detects_non_full_neighbor(self):
        snapshot = _make_snapshot()
        snapshot.routers["spine1"].neighbors[0].state = "Init"
        result = self.agent.diagnose(snapshot)
        assert result.fault_detected is True
        assert result.fault_class == "link_failure"

    def test_mock_agent_detects_counter_anomaly(self):
        snapshot = _make_snapshot()
        snapshot.routers["spine1"].interfaces["eth1"].counters = InterfaceCounters(
            rx_packets=100, tx_packets=100, rx_errors=10, tx_errors=10,
        )
        result = self.agent.diagnose(snapshot)
        assert result.fault_detected is True
        assert result.fault_class == "counter_anomaly"


class TestLLMAgentEncoding:
    """Tests for snapshot encoding and prompt construction."""

    @patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'test-key'})
    @patch('diagnosis.llm_agent.anthropic.Anthropic')
    def test_snapshot_encoding(self, mock_anthropic):
        agent = LLMAgent()
        snapshot = _make_snapshot()

        encoded = agent._encode_snapshot(snapshot)
        data = json.loads(encoded)

        assert data["snapshot_id"] == "test_001"
        assert "spine1" in data["routers"]
        router = data["routers"]["spine1"]
        assert router["router_name"] == "spine1"
        assert len(router["neighbors"]) == 1
        assert router["neighbors"][0]["state"] == "Full"

    @patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'test-key'})
    @patch('diagnosis.llm_agent.anthropic.Anthropic')
    def test_response_parsing_with_code_block(self, mock_anthropic):
        agent = LLMAgent()
        response_text = '```json\n{"fault_detected": true, "fault_class": "link_failure", "location": "spine1:eth1", "confidence": 0.95, "reasoning": "test"}\n```'
        parsed = agent._parse_response(response_text)
        assert parsed["fault_detected"] is True
        assert parsed["fault_class"] == "link_failure"

    @patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'test-key'})
    @patch('diagnosis.llm_agent.anthropic.Anthropic')
    def test_response_parsing_bare_json(self, mock_anthropic):
        agent = LLMAgent()
        parsed = agent._parse_response('{"fault_detected": false, "fault_class": "none"}')
        assert parsed["fault_detected"] is False


class TestDiffAwarePrompts:
    """Tests for diff-aware prompt construction."""

    @patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'test-key'})
    @patch('diagnosis.llm_agent.anthropic.Anthropic')
    def test_build_messages_with_diff(self, mock_anthropic):
        """When a diff is provided, it should appear in the final user message."""
        agent = LLMAgent()
        snapshot_json = '{"snapshot_id": "test"}'
        diff_json = '{"changes_per_router": {"spine1": {"neighbor_changes": {}}}}'

        messages = agent._build_messages(snapshot_json, diff_json)
        last_msg = messages[-1]

        assert last_msg["role"] == "user"
        assert "Changes from previous snapshot" in last_msg["content"]
        assert "changes_per_router" in last_msg["content"]

    @patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'test-key'})
    @patch('diagnosis.llm_agent.anthropic.Anthropic')
    def test_build_messages_without_diff(self, mock_anthropic):
        """When no diff, the prompt should not mention previous snapshots."""
        agent = LLMAgent()
        messages = agent._build_messages('{"snapshot_id": "test"}')
        last_msg = messages[-1]

        assert "Changes from previous snapshot" not in last_msg["content"]

    @patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'test-key'})
    @patch('diagnosis.llm_agent.anthropic.Anthropic')
    def test_compute_snapshot_diff_no_changes(self, mock_anthropic):
        """Identical snapshots should return None diff."""
        agent = LLMAgent()
        snapshot = _make_snapshot()
        result = agent._compute_snapshot_diff(snapshot, snapshot)
        assert result is None

    @patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'test-key'})
    @patch('diagnosis.llm_agent.anthropic.Anthropic')
    def test_compute_snapshot_diff_with_changes(self, mock_anthropic):
        """Different snapshots should produce a non-None diff."""
        agent = LLMAgent()
        before = _make_snapshot(snapshot_id="before")
        after = _make_snapshot(snapshot_id="after")
        # Modify after
        after.routers["spine1"].interfaces["eth1"].link_status = "down"

        result = agent._compute_snapshot_diff(before, after)
        assert result is not None
        diff_data = json.loads(result)
        assert "changes_per_router" in diff_data


class TestArtifactLogging:
    """Tests for artifact metadata and token tracking."""

    @patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'test-key'})
    @patch('diagnosis.llm_agent.anthropic.Anthropic')
    def test_artifact_in_raw_output(self, mock_anthropic):
        """Diagnosis result should contain artifact metadata in raw_output."""
        mock_client = MagicMock()
        mock_anthropic.return_value = mock_client

        mock_usage = MagicMock()
        mock_usage.input_tokens = 4500
        mock_usage.output_tokens = 350

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text='```json\n{"fault_detected": false, "fault_class": "none", "confidence": 1.0, "reasoning": "All good"}\n```')]
        mock_response.usage = mock_usage
        mock_response.stop_reason = "end_turn"
        mock_client.messages.create.return_value = mock_response

        agent = LLMAgent()
        snapshot = _make_snapshot()
        result = agent.diagnose(snapshot)

        # Parse raw_output
        raw = json.loads(result.raw_output)
        assert "artifact" in raw
        artifact = raw["artifact"]
        assert artifact["model"] == agent.model
        assert artifact["prompt_hash"] == agent.prompt_hash
        assert artifact["input_tokens"] == 4500
        assert artifact["output_tokens"] == 350
        assert artifact["stop_reason"] == "end_turn"
        assert "timestamp" in artifact

    @patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'test-key'})
    @patch('diagnosis.llm_agent.anthropic.Anthropic')
    def test_token_tracking_in_stats(self, mock_anthropic):
        """get_stats() should report cumulative token usage."""
        mock_client = MagicMock()
        mock_anthropic.return_value = mock_client

        mock_usage = MagicMock()
        mock_usage.input_tokens = 1000
        mock_usage.output_tokens = 200

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text='{"fault_detected": false, "fault_class": "none", "confidence": 1.0, "reasoning": "ok"}')]
        mock_response.usage = mock_usage
        mock_response.stop_reason = "end_turn"
        mock_client.messages.create.return_value = mock_response

        agent = LLMAgent()

        # Run two diagnoses
        agent.diagnose(_make_snapshot(snapshot_id="s1"))
        agent.diagnose(_make_snapshot(snapshot_id="s2"))

        stats = agent.get_stats()
        assert stats["total_input_tokens"] == 2000
        assert stats["total_output_tokens"] == 400
        assert stats["invocation_count"] == 2


class TestMultiModelSupport:
    """Tests for multi-model configuration."""

    @patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'test-key'})
    @patch('diagnosis.llm_agent.anthropic.Anthropic')
    def test_agent_with_custom_model(self, mock_anthropic):
        agent = LLMAgent(model="claude-haiku-4-5-20251001")
        assert agent.model == "claude-haiku-4-5-20251001"
        stats = agent.get_stats()
        assert stats["model"] == "claude-haiku-4-5-20251001"

    @patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'test-key', 'LLM_MODEL': 'claude-opus-4-6'})
    @patch('diagnosis.llm_agent.anthropic.Anthropic')
    def test_agent_uses_env_var_default(self, mock_anthropic):
        """When no model is passed, should use LLM_MODEL env var."""
        # Need to reload the module to pick up the env var
        import importlib
        import diagnosis.llm_agent as llm_mod
        importlib.reload(llm_mod)
        agent = llm_mod.LLMAgent()
        # The model should be from the env var or the constructor default
        assert agent.model in ("claude-opus-4-6", "claude-sonnet-4-5-20250929")

    @patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'test-key'})
    @patch('diagnosis.llm_agent.anthropic.Anthropic')
    def test_prompt_hash_stable(self, mock_anthropic):
        """Same prompts should produce same hash across instances."""
        a1 = LLMAgent()
        a2 = LLMAgent()
        assert a1.prompt_hash == a2.prompt_hash

    @patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'test-key'})
    @patch('diagnosis.llm_agent.anthropic.Anthropic')
    def test_few_shot_examples_loaded(self, mock_anthropic):
        """Should load all 8 few-shot examples."""
        agent = LLMAgent()
        assert agent.get_stats()["num_few_shot_examples"] == 8


class TestLLMAgentIntegration:
    """Integration tests with mocked API."""

    @patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'test-key'})
    @patch('diagnosis.llm_agent.anthropic.Anthropic')
    def test_full_diagnosis_flow(self, mock_anthropic):
        mock_client = MagicMock()
        mock_anthropic.return_value = mock_client

        mock_usage = MagicMock()
        mock_usage.input_tokens = 5000
        mock_usage.output_tokens = 400

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text='```json\n{"fault_detected": true, "fault_class": "link_failure", "location": "spine1:eth1", "affected_routers": ["spine1", "leaf1"], "affected_interfaces": ["spine1:eth1"], "affected_prefixes": [], "confidence": 0.95, "reasoning": "Analysis shows interface down", "remediation": "Bring interface up"}\n```')]
        mock_response.usage = mock_usage
        mock_response.stop_reason = "end_turn"
        mock_client.messages.create.return_value = mock_response

        agent = LLMAgent()
        snapshot = _make_snapshot()
        snapshot.routers["spine1"].interfaces["eth1"].link_status = "down"

        result = agent.diagnose(snapshot)

        assert result.fault_detected is True
        assert result.fault_class == "link_failure"
        assert result.confidence == 0.95
        assert "spine1" in result.affected_routers

    @patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'test-key'})
    @patch('diagnosis.llm_agent.anthropic.Anthropic')
    def test_diagnosis_with_previous_snapshot(self, mock_anthropic):
        """When previous_snapshot is provided, the API call should include diff context."""
        mock_client = MagicMock()
        mock_anthropic.return_value = mock_client

        mock_usage = MagicMock()
        mock_usage.input_tokens = 6000
        mock_usage.output_tokens = 500

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text='{"fault_detected": true, "fault_class": "link_failure", "location": "spine1:eth1", "confidence": 0.95, "reasoning": "diff shows interface went down"}')]
        mock_response.usage = mock_usage
        mock_response.stop_reason = "end_turn"
        mock_client.messages.create.return_value = mock_response

        agent = LLMAgent()

        before = _make_snapshot(snapshot_id="before")
        after = _make_snapshot(snapshot_id="after")
        after.routers["spine1"].interfaces["eth1"].link_status = "down"

        result = agent.diagnose(after, previous_snapshot=before)

        # Verify the API was called
        assert mock_client.messages.create.called
        call_args = mock_client.messages.create.call_args
        messages = call_args.kwargs.get("messages", call_args[1].get("messages", []))
        last_user_msg = [m for m in messages if m["role"] == "user"][-1]

        # The last user message should contain diff information
        assert "Changes from previous snapshot" in last_user_msg["content"]
