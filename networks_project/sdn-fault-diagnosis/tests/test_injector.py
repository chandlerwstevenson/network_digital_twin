"""
Unit tests for fault injection system.
"""

from unittest.mock import MagicMock, patch

import pytest

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from faults.fault_types import (
    CounterAnomaly,
    FaultClass,
    FaultResult,
    FlappingLink,
    LinkFailure,
    MissingRoute,
    StaleRoute,
    create_fault,
)
from faults.injector import FaultInjector
from faults.scenarios import (
    ALL_SCENARIOS,
    SINGLE_FAULT_SCENARIOS,
    COMPOUND_FAULT_SCENARIOS,
    FaultSpec,
    Scenario,
    ScenarioType,
    get_balanced_scenario_set,
    get_scenarios_by_fault_class,
)


class TestFaultTypes:
    """Tests for fault type classes."""

    def test_link_failure_to_dict(self):
        """Test LinkFailure serialization."""
        fault = LinkFailure(
            container="spine1",
            interface="eth1"
        )

        data = fault.to_dict()

        assert data["fault_class"] == "link_failure"
        assert data["container"] == "spine1"
        assert data["interface"] == "eth1"
        assert data["injected"] is False

    def test_stale_route_to_dict(self):
        """Test StaleRoute serialization."""
        fault = StaleRoute(
            container="leaf1",
            prefix="192.168.4.0/24",
            nexthop="10.1.1.0",
            distance=1
        )

        data = fault.to_dict()

        assert data["fault_class"] == "stale_route"
        assert data["prefix"] == "192.168.4.0/24"
        assert data["nexthop"] == "10.1.1.0"
        assert data["distance"] == 1

    def test_counter_anomaly_to_dict(self):
        """Test CounterAnomaly serialization."""
        fault = CounterAnomaly(
            container="spine1",
            interface="eth1",
            loss_pct=5.0,
            corrupt_pct=1.0
        )

        data = fault.to_dict()

        assert data["fault_class"] == "counter_anomaly"
        assert data["loss_pct"] == 5.0
        assert data["corrupt_pct"] == 1.0

    def test_create_fault_link_failure(self):
        """Test fault factory for link failure."""
        config = {
            "fault_class": "link_failure",
            "container": "spine1",
            "interface": "eth2"
        }

        fault = create_fault(config)

        assert isinstance(fault, LinkFailure)
        assert fault.container == "spine1"
        assert fault.interface == "eth2"

    def test_create_fault_stale_route(self):
        """Test fault factory for stale route."""
        config = {
            "fault_class": "stale_route",
            "container": "leaf2",
            "prefix": "10.0.0.0/8",
            "nexthop": "192.168.1.1",
            "distance": 5
        }

        fault = create_fault(config)

        assert isinstance(fault, StaleRoute)
        assert fault.prefix == "10.0.0.0/8"
        assert fault.distance == 5

    def test_create_fault_unknown_type(self):
        """Test fault factory with unknown type."""
        config = {
            "fault_class": "unknown_type",
            "container": "spine1"
        }

        with pytest.raises(ValueError, match="Unknown fault class"):
            create_fault(config)


class TestFaultInjector:
    """Tests for FaultInjector class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.injector = FaultInjector(container_prefix="test-prefix")

    def test_generate_fault_id(self):
        """Test unique fault ID generation."""
        id1 = self.injector._generate_fault_id()
        id2 = self.injector._generate_fault_id()

        assert id1 != id2
        assert id1.startswith("fault_")
        assert id2.startswith("fault_")

    @patch.object(LinkFailure, 'inject')
    @patch.object(LinkFailure, 'verify')
    def test_inject_link_failure(self, mock_verify, mock_inject):
        """Test link failure injection."""
        mock_inject.return_value = FaultResult(
            success=True,
            message="Interface down"
        )
        mock_verify.return_value = True

        fault_id, result = self.injector.inject_link_failure("spine1", "eth1")

        assert result.success is True
        assert fault_id in self.injector.state.active_faults
        mock_inject.assert_called_once()

    @patch.object(StaleRoute, 'inject')
    @patch.object(StaleRoute, 'verify')
    def test_inject_stale_route(self, mock_verify, mock_inject):
        """Test stale route injection."""
        mock_inject.return_value = FaultResult(
            success=True,
            message="Static route added"
        )
        mock_verify.return_value = True

        fault_id, result = self.injector.inject_stale_route(
            "leaf1",
            "192.168.4.0/24",
            "10.1.1.0"
        )

        assert result.success is True
        assert len(self.injector.state.active_faults) == 1

    @patch.object(LinkFailure, 'inject')
    @patch.object(LinkFailure, 'verify')
    @patch.object(LinkFailure, 'restore')
    def test_restore_fault(self, mock_restore, mock_verify, mock_inject):
        """Test fault restoration."""
        mock_inject.return_value = FaultResult(success=True, message="OK")
        mock_verify.return_value = True
        mock_restore.return_value = FaultResult(success=True, message="Restored")

        fault_id, _ = self.injector.inject_link_failure("spine1", "eth1")
        assert fault_id in self.injector.state.active_faults

        result = self.injector.restore_fault(fault_id)

        assert result.success is True
        assert fault_id not in self.injector.state.active_faults

    def test_restore_nonexistent_fault(self):
        """Test restoring a fault that doesn't exist."""
        result = self.injector.restore_fault("nonexistent_id")

        assert result.success is False

    def test_get_active_faults_empty(self):
        """Test getting active faults when none exist."""
        faults = self.injector.get_active_faults()

        assert faults == {}

    def test_get_fault_history(self):
        """Test getting fault history."""
        # Initially empty
        history = self.injector.get_fault_history()
        assert history == []


class TestScenarios:
    """Tests for fault scenarios."""

    def test_single_fault_scenarios_count(self):
        """Test that we have expected number of single fault scenarios."""
        assert len(SINGLE_FAULT_SCENARIOS) > 0

    def test_compound_fault_scenarios_count(self):
        """Test that we have expected number of compound fault scenarios."""
        assert len(COMPOUND_FAULT_SCENARIOS) > 0

    def test_all_scenarios_combined(self):
        """Test ALL_SCENARIOS contains all scenarios."""
        assert len(ALL_SCENARIOS) == (
            len(SINGLE_FAULT_SCENARIOS) + len(COMPOUND_FAULT_SCENARIOS)
        )

    def test_scenario_structure(self):
        """Test that scenarios have required attributes."""
        for scenario in ALL_SCENARIOS:
            assert isinstance(scenario.name, str)
            assert isinstance(scenario.description, str)
            assert isinstance(scenario.faults, list)
            assert len(scenario.faults) >= 1
            assert isinstance(scenario.scenario_type, ScenarioType)

    def test_single_scenarios_have_one_fault(self):
        """Test that single scenarios have exactly one fault."""
        for scenario in SINGLE_FAULT_SCENARIOS:
            assert len(scenario.faults) == 1
            assert scenario.scenario_type == ScenarioType.SINGLE
            assert not scenario.is_compound

    def test_compound_scenarios_have_multiple_faults(self):
        """Test that compound scenarios have multiple faults."""
        for scenario in COMPOUND_FAULT_SCENARIOS:
            assert len(scenario.faults) >= 2
            assert scenario.scenario_type == ScenarioType.COMPOUND
            assert scenario.is_compound

    def test_get_scenarios_by_fault_class(self):
        """Test filtering scenarios by fault class."""
        link_failure_scenarios = get_scenarios_by_fault_class(
            FaultClass.LINK_FAILURE
        )

        assert len(link_failure_scenarios) > 0
        for scenario in link_failure_scenarios:
            assert FaultClass.LINK_FAILURE in scenario.fault_classes

    def test_get_balanced_scenario_set(self):
        """Test balanced scenario set generation."""
        scenarios = get_balanced_scenario_set(
            total=20,
            compound_ratio=0.2
        )

        assert len(scenarios) == 20

        # Check compound ratio
        compound_count = sum(1 for s in scenarios if s.is_compound)
        assert compound_count == 4  # 20 * 0.2

    def test_fault_spec_to_dict(self):
        """Test FaultSpec serialization."""
        spec = FaultSpec(
            fault_class=FaultClass.LINK_FAILURE,
            container="spine1",
            params={"interface": "eth1"}
        )

        data = spec.to_dict()

        assert data["fault_class"] == "link_failure"
        assert data["container"] == "spine1"
        assert data["interface"] == "eth1"
