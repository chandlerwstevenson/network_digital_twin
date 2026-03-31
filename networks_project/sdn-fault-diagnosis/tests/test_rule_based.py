"""
Unit tests for rule-based diagnostic engine.
"""

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
    Route,
    RouteNexthop,
    RouterLSA,
    RouterTelemetry,
    RoutingTable,
)
from diagnosis.rule_based import RuleBasedEngine, Finding, AnalysisState
from diagnosis.base import DiagnosisConfig


class TestRuleBasedEngine:
    """Tests for RuleBasedEngine class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.engine = RuleBasedEngine()

    def create_healthy_snapshot(self) -> NetworkSnapshot:
        """Create a healthy network snapshot for testing."""
        return NetworkSnapshot(
            snapshot_id="healthy_001",
            routers={
                "spine1": RouterTelemetry(
                    router_name="spine1",
                    router_id="10.0.0.1",
                    neighbors=[
                        OSPFNeighbor(
                            neighbor_id="10.0.1.1",
                            state="Full",
                            address="10.1.1.1",
                            interface="eth1"
                        ),
                        OSPFNeighbor(
                            neighbor_id="10.0.1.2",
                            state="Full",
                            address="10.1.1.3",
                            interface="eth2"
                        ),
                    ],
                    interfaces={
                        "eth1": Interface(
                            name="eth1",
                            link_status="up",
                            counters=InterfaceCounters()
                        ),
                        "eth2": Interface(
                            name="eth2",
                            link_status="up",
                            counters=InterfaceCounters()
                        ),
                    },
                    lsdb=OSPFLSDB(
                        router_lsas=[
                            RouterLSA(
                                lsa_id="10.0.0.1",
                                advertising_router="10.0.0.1",
                                link_count=4
                            ),
                            RouterLSA(
                                lsa_id="10.0.1.1",
                                advertising_router="10.0.1.1",
                                link_count=6
                            ),
                        ]
                    ),
                    routing_table=RoutingTable(routes={
                        "192.168.1.0/24": [Route(prefix="192.168.1.0", prefix_len=24, protocol="ospf", distance=110, nexthops=[RouteNexthop(ip="10.0.1.1", interface="eth1")])],
                        "192.168.2.0/24": [Route(prefix="192.168.2.0", prefix_len=24, protocol="ospf", distance=110, nexthops=[RouteNexthop(ip="10.0.1.2", interface="eth2")])],
                        "192.168.3.0/24": [Route(prefix="192.168.3.0", prefix_len=24, protocol="ospf", distance=110, nexthops=[RouteNexthop(ip="10.0.1.3", interface="eth3")])],
                        "192.168.4.0/24": [Route(prefix="192.168.4.0", prefix_len=24, protocol="ospf", distance=110, nexthops=[RouteNexthop(ip="10.0.1.4", interface="eth4")])],
                    })
                ),
                "leaf1": RouterTelemetry(
                    router_name="leaf1",
                    router_id="10.0.1.1",
                    neighbors=[
                        OSPFNeighbor(
                            neighbor_id="10.0.0.1",
                            state="Full",
                            address="10.1.1.0",
                            interface="eth1"
                        ),
                    ],
                    interfaces={
                        "eth1": Interface(
                            name="eth1",
                            link_status="up",
                            counters=InterfaceCounters()
                        ),
                    },
                    lsdb=OSPFLSDB(
                        router_lsas=[
                            RouterLSA(
                                lsa_id="10.0.0.1",
                                advertising_router="10.0.0.1",
                                link_count=4
                            ),
                            RouterLSA(
                                lsa_id="10.0.1.1",
                                advertising_router="10.0.1.1",
                                link_count=6
                            ),
                        ]
                    ),
                    routing_table=RoutingTable(routes={})
                ),
            }
        )

    def test_healthy_network_no_fault(self):
        """Test that healthy network produces no fault diagnosis."""
        snapshot = self.create_healthy_snapshot()
        result = self.engine.diagnose(snapshot)

        assert result.fault_detected is False
        assert result.fault_class is None

    def test_detects_neighbor_down(self):
        """Test detection of non-Full neighbor."""
        snapshot = self.create_healthy_snapshot()

        # Modify to have a non-Full neighbor
        snapshot.routers["spine1"].neighbors[0].state = "Init"

        result = self.engine.diagnose(snapshot)

        assert result.fault_detected is True
        assert result.fault_class == "link_failure"
        assert "spine1" in result.affected_routers

    def test_detects_interface_down(self):
        """Test detection of interface down."""
        snapshot = self.create_healthy_snapshot()

        # Modify to have a down interface
        snapshot.routers["spine1"].interfaces["eth1"].link_status = "down"
        snapshot.routers["spine1"].neighbors[0].state = "Down"

        result = self.engine.diagnose(snapshot)

        assert result.fault_detected is True
        assert result.fault_class == "link_failure"
        assert "spine1:eth1" in result.location

    def test_detects_counter_anomaly(self):
        """Test detection of high error/drop rates."""
        snapshot = self.create_healthy_snapshot()

        # Modify to have high error rate
        snapshot.routers["spine1"].interfaces["eth1"].counters = InterfaceCounters(
            rx_packets=100,
            tx_packets=100,
            rx_errors=10,
            tx_errors=10
        )

        result = self.engine.diagnose(snapshot)

        assert result.fault_detected is True
        assert result.fault_class == "counter_anomaly"
        assert "spine1:eth1" in result.affected_interfaces

    def test_detects_stale_route(self):
        """Test detection of static route (potential stale route)."""
        snapshot = self.create_healthy_snapshot()

        # Add a suspicious static route
        snapshot.routers["leaf1"].routing_table.routes["192.168.4.0/24"] = [
            Route(
                prefix="192.168.4.0",
                prefix_len=24,
                protocol="static",
                distance=1,
                nexthops=[
                    RouteNexthop(ip="10.1.1.0", interface="eth1")
                ]
            )
        ]

        result = self.engine.diagnose(snapshot)

        assert result.fault_detected is True
        assert result.fault_class == "stale_route"

    def test_engine_reset(self):
        """Test that engine reset clears history."""
        snapshot = self.create_healthy_snapshot()

        # Process a snapshot
        self.engine.diagnose_with_history(snapshot)
        assert self.engine.has_history

        # Reset
        self.engine.reset()
        assert not self.engine.has_history
        assert self.engine._diagnosis_count == 0


class TestAnalysisState:
    """Tests for AnalysisState class."""

    def test_add_finding(self):
        """Test adding findings to analysis state."""
        state = AnalysisState()

        finding = Finding(
            category="neighbor",
            severity="critical",
            router="spine1",
            component="eth1",
            description="Test finding"
        )
        state.add_finding(finding)

        assert len(state.findings) == 1
        assert "spine1" in state.affected_routers
        assert "spine1:eth1" in state.affected_interfaces

    def test_has_critical(self):
        """Test has_critical property."""
        state = AnalysisState()

        # Add warning finding
        state.add_finding(Finding(
            category="counter",
            severity="warning",
            router="spine1",
            component="eth1",
            description="Warning"
        ))
        assert not state.has_critical

        # Add critical finding
        state.add_finding(Finding(
            category="neighbor",
            severity="critical",
            router="spine1",
            component="eth1",
            description="Critical"
        ))
        assert state.has_critical

    def test_critical_findings(self):
        """Test filtering critical findings."""
        state = AnalysisState()

        state.add_finding(Finding(
            category="counter",
            severity="warning",
            router="spine1",
            component="eth1",
            description="Warning"
        ))
        state.add_finding(Finding(
            category="neighbor",
            severity="critical",
            router="spine1",
            component="eth1",
            description="Critical 1"
        ))
        state.add_finding(Finding(
            category="neighbor",
            severity="critical",
            router="spine2",
            component="eth2",
            description="Critical 2"
        ))

        assert len(state.critical_findings) == 2
        assert len(state.warning_findings) == 1


class TestDiagnosisConfig:
    """Tests for DiagnosisConfig class."""

    def test_default_config(self):
        """Test default configuration values."""
        config = DiagnosisConfig()

        assert config.error_rate_threshold == 1.0
        assert config.drop_rate_threshold == 1.0
        assert config.require_full_adjacency is True
        assert config.min_confidence == 0.5

    def test_custom_config(self):
        """Test custom configuration."""
        config = DiagnosisConfig(
            error_rate_threshold=2.0,
            drop_rate_threshold=3.0,
            require_full_adjacency=False,
            min_confidence=0.8
        )

        assert config.error_rate_threshold == 2.0
        assert config.drop_rate_threshold == 3.0
        assert config.require_full_adjacency is False
        assert config.min_confidence == 0.8
