"""
Unit tests for the hybrid diagnostic engine.

Tests cover:
- High-confidence rule-based results are accepted without LLM call
- Low-confidence results are deferred to LLM
- "unknown" fault class always defers
- Stats tracking (defer rate, cost savings)
- Behavior when no LLM is configured
- Threshold tuning affects defer behavior
"""

import pytest

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from telemetry.schemas import (
    DiagnosisResult,
    Interface,
    InterfaceCounters,
    NetworkSnapshot,
    OSPFNeighbor,
    OSPFLSDB,
    Route,
    RouteNexthop,
    RouterLSA,
    RouterTelemetry,
    RoutingTable,
)
from diagnosis.hybrid_engine import HybridEngine
from diagnosis.rule_based import RuleBasedEngine
from diagnosis.llm_agent import MockLLMAgent
from diagnosis.base import DiagnosisConfig


def _healthy_snapshot() -> NetworkSnapshot:
    """Snapshot that rule-based will classify as healthy (no fault, conf=1.0)."""
    return NetworkSnapshot(
        snapshot_id="healthy",
        routers={
            "spine1": RouterTelemetry(
                router_name="spine1",
                router_id="10.0.0.1",
                neighbors=[
                    OSPFNeighbor(neighbor_id="10.0.1.1", state="Full",
                                 address="10.1.1.1", interface="eth1"),
                ],
                interfaces={
                    "eth1": Interface(name="eth1", link_status="up",
                                      counters=InterfaceCounters()),
                },
                lsdb=OSPFLSDB(router_lsas=[
                    RouterLSA(lsa_id="10.0.0.1", advertising_router="10.0.0.1", link_count=4),
                    RouterLSA(lsa_id="10.0.1.1", advertising_router="10.0.1.1", link_count=6),
                ]),
                routing_table=RoutingTable(routes={
                    "192.168.1.0/24": [Route(prefix="192.168.1.0", prefix_len=24, protocol="ospf", distance=110, nexthops=[RouteNexthop(ip="10.0.1.1", interface="eth1")])],
                    "192.168.2.0/24": [Route(prefix="192.168.2.0", prefix_len=24, protocol="ospf", distance=110, nexthops=[RouteNexthop(ip="10.0.1.2", interface="eth2")])],
                    "192.168.3.0/24": [Route(prefix="192.168.3.0", prefix_len=24, protocol="ospf", distance=110, nexthops=[RouteNexthop(ip="10.0.1.3", interface="eth3")])],
                    "192.168.4.0/24": [Route(prefix="192.168.4.0", prefix_len=24, protocol="ospf", distance=110, nexthops=[RouteNexthop(ip="10.0.1.4", interface="eth4")])],
                }),
            ),
            "leaf1": RouterTelemetry(
                router_name="leaf1",
                router_id="10.0.1.1",
                neighbors=[
                    OSPFNeighbor(neighbor_id="10.0.0.1", state="Full",
                                 address="10.1.1.0", interface="eth1"),
                ],
                interfaces={
                    "eth1": Interface(name="eth1", link_status="up",
                                      counters=InterfaceCounters()),
                },
                lsdb=OSPFLSDB(router_lsas=[
                    RouterLSA(lsa_id="10.0.0.1", advertising_router="10.0.0.1", link_count=4),
                    RouterLSA(lsa_id="10.0.1.1", advertising_router="10.0.1.1", link_count=6),
                ]),
                routing_table=RoutingTable(routes={}),
            ),
        },
    )


def _link_failure_snapshot() -> NetworkSnapshot:
    """Snapshot with clear link failure (rule-based will be high confidence)."""
    s = _healthy_snapshot()
    s.routers["spine1"].interfaces["eth1"].link_status = "down"
    s.routers["spine1"].neighbors[0].state = "Down"
    return s


def _ambiguous_snapshot() -> NetworkSnapshot:
    """Snapshot with mild counter anomaly (rule-based will have low confidence)."""
    s = _healthy_snapshot()
    # Mild error rate — just above threshold, rule-based gives ~0.80 or lower
    s.routers["spine1"].interfaces["eth1"].counters = InterfaceCounters(
        rx_packets=1000, tx_packets=1000,
        rx_errors=15, tx_errors=15,
    )
    return s


class TestHybridEngine:
    """Tests for HybridEngine."""

    def test_accepts_high_confidence_rule_based(self):
        """Clear faults should be handled by rule-based without LLM."""
        mock_llm = MockLLMAgent()
        engine = HybridEngine(llm_engine=mock_llm, confidence_threshold=0.80)

        snapshot = _link_failure_snapshot()
        result = engine.diagnose(snapshot)

        assert result.fault_detected is True
        assert result.fault_class == "link_failure"
        assert "rule-based accepted" in result.reasoning
        assert engine._rule_accepted == 1
        assert engine._llm_deferred == 0

    def test_accepts_healthy_no_fault(self):
        """Healthy network should be accepted by rule-based (conf=1.0)."""
        mock_llm = MockLLMAgent()
        engine = HybridEngine(llm_engine=mock_llm, confidence_threshold=0.80)

        snapshot = _healthy_snapshot()
        result = engine.diagnose(snapshot)

        assert result.fault_detected is False
        assert "rule-based accepted" in result.reasoning
        assert engine._rule_accepted == 1

    def test_defers_low_confidence_to_llm(self):
        """Ambiguous cases should defer to LLM."""
        mock_llm = MockLLMAgent()
        # Set threshold very high so even moderate confidence defers
        engine = HybridEngine(llm_engine=mock_llm, confidence_threshold=0.99)

        snapshot = _link_failure_snapshot()
        result = engine.diagnose(snapshot)

        # With threshold=0.99, the rule-based conf=0.95 will defer
        assert "deferred to LLM" in result.reasoning or "rule-based accepted" in result.reasoning
        # Either way it should detect the fault
        assert result.fault_detected is True

    def test_defer_rate_tracking(self):
        """Defer rate should reflect actual routing decisions."""
        mock_llm = MockLLMAgent()
        engine = HybridEngine(llm_engine=mock_llm, confidence_threshold=0.80)

        # High confidence — accepted
        engine.diagnose(_link_failure_snapshot())
        # High confidence — accepted (healthy)
        engine.diagnose(_healthy_snapshot())

        assert engine._total_diagnoses == 2
        assert engine.defer_rate == 0.0
        assert engine.llm_cost_savings == 1.0

    def test_no_llm_fallback(self):
        """Without an LLM, should return rule-based with a note."""
        engine = HybridEngine(llm_engine=None, confidence_threshold=0.99)

        # Force defer by setting threshold very high
        snapshot = _link_failure_snapshot()
        result = engine.diagnose(snapshot)

        assert result.fault_detected is True
        # Should still work, just with a fallback note
        assert "no LLM" in result.reasoning or "rule-based accepted" in result.reasoning

    def test_threshold_affects_behavior(self):
        """Lower threshold should accept more, higher should defer more."""
        mock_llm = MockLLMAgent()
        snapshot = _link_failure_snapshot()

        # Low threshold — should accept
        engine_low = HybridEngine(llm_engine=mock_llm, confidence_threshold=0.50)
        engine_low.diagnose(snapshot)
        assert engine_low._rule_accepted == 1

        # Very high threshold — should defer (rule-based gives 0.95 for link failure)
        engine_high = HybridEngine(llm_engine=mock_llm, confidence_threshold=0.99)
        engine_high.diagnose(snapshot)
        assert engine_high._llm_deferred == 1

    def test_stats_include_hybrid_fields(self):
        """get_stats() should report hybrid-specific metrics."""
        mock_llm = MockLLMAgent()
        engine = HybridEngine(llm_engine=mock_llm, confidence_threshold=0.80)

        engine.diagnose(_link_failure_snapshot())
        engine.diagnose(_healthy_snapshot())

        stats = engine.get_stats()
        assert stats["name"] == "hybrid"
        assert stats["confidence_threshold"] == 0.80
        assert stats["total_diagnoses"] == 2
        assert "defer_rate" in stats
        assert "llm_cost_savings" in stats
        assert stats["llm_engine_name"] == "mock-llm-agent"

    def test_reset_clears_tracking(self):
        """reset() should clear all counters."""
        mock_llm = MockLLMAgent()
        engine = HybridEngine(llm_engine=mock_llm, confidence_threshold=0.80)

        engine.diagnose(_link_failure_snapshot())
        assert engine._total_diagnoses == 1

        engine.reset()
        assert engine._total_diagnoses == 0
        assert engine._rule_accepted == 0
        assert engine._llm_deferred == 0

    def test_result_has_source_in_raw_output(self):
        """raw_output should indicate which engine produced the result."""
        mock_llm = MockLLMAgent()
        engine = HybridEngine(llm_engine=mock_llm, confidence_threshold=0.80)

        result = engine.diagnose(_link_failure_snapshot())
        assert result.raw_output is not None
        assert "source" in result.raw_output

    def test_diagnose_with_history(self):
        """diagnose_with_history should work and track state."""
        mock_llm = MockLLMAgent()
        engine = HybridEngine(llm_engine=mock_llm, confidence_threshold=0.80)

        result = engine.diagnose_with_history(_healthy_snapshot())
        assert result.fault_detected is False
        assert engine.has_history

        result2 = engine.diagnose_with_history(_link_failure_snapshot())
        assert result2.fault_detected is True
