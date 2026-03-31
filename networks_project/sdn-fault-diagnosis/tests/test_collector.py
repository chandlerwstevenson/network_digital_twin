"""
Unit tests for telemetry collection.
"""

import json
from datetime import datetime
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
    Route,
    RouteNexthop,
    RouterLSA,
    RouterTelemetry,
    RoutingTable,
)
from telemetry.collector import TelemetryCollector


class TestSchemas:
    """Tests for Pydantic schemas."""

    def test_ospf_neighbor_is_full(self):
        """Test OSPFNeighbor.is_full property."""
        neighbor_full = OSPFNeighbor(
            neighbor_id="10.0.0.1",
            state="Full",
            address="10.1.1.0",
            interface="eth1"
        )
        assert neighbor_full.is_full

        neighbor_init = OSPFNeighbor(
            neighbor_id="10.0.0.1",
            state="Init",
            address="10.1.1.0",
            interface="eth1"
        )
        assert not neighbor_init.is_full

    def test_interface_counters_error_rate(self):
        """Test InterfaceCounters.error_rate calculation."""
        counters = InterfaceCounters(
            rx_packets=100,
            tx_packets=100,
            rx_errors=5,
            tx_errors=5
        )
        assert counters.error_rate == 5.0  # (10 errors / 200 packets) * 100

    def test_interface_counters_drop_rate(self):
        """Test InterfaceCounters.drop_rate calculation."""
        counters = InterfaceCounters(
            rx_packets=100,
            tx_packets=100,
            rx_dropped=2,
            tx_dropped=2
        )
        assert counters.drop_rate == 2.0  # (4 drops / 200 packets) * 100

    def test_interface_counters_zero_packets(self):
        """Test counters handle zero packets gracefully."""
        counters = InterfaceCounters()
        assert counters.error_rate == 0.0
        assert counters.drop_rate == 0.0

    def test_router_telemetry_adjacencies(self):
        """Test RouterTelemetry adjacency filtering."""
        telemetry = RouterTelemetry(
            router_name="spine1",
            neighbors=[
                OSPFNeighbor(
                    neighbor_id="10.0.1.1",
                    state="Full",
                    address="10.1.1.1",
                    interface="eth1"
                ),
                OSPFNeighbor(
                    neighbor_id="10.0.1.2",
                    state="Init",
                    address="10.1.1.3",
                    interface="eth2"
                ),
                OSPFNeighbor(
                    neighbor_id="10.0.1.3",
                    state="Full",
                    address="10.1.1.5",
                    interface="eth3"
                ),
            ]
        )
        assert len(telemetry.full_adjacencies) == 2
        assert len(telemetry.non_full_adjacencies) == 1

    def test_network_snapshot_stats(self):
        """Test NetworkSnapshot statistics properties."""
        snapshot = NetworkSnapshot(
            snapshot_id="test_001",
            routers={
                "spine1": RouterTelemetry(
                    router_name="spine1",
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
                    ]
                ),
                "leaf1": RouterTelemetry(
                    router_name="leaf1",
                    neighbors=[
                        OSPFNeighbor(
                            neighbor_id="10.0.0.1",
                            state="Full",
                            address="10.1.1.0",
                            interface="eth1"
                        ),
                    ]
                ),
            }
        )
        assert len(snapshot.router_names) == 2
        assert snapshot.total_neighbors == 3
        assert snapshot.total_full_adjacencies == 3


class TestTelemetryCollector:
    """Tests for TelemetryCollector class."""

    @patch('telemetry.collector.subprocess.run')
    def test_exec_vtysh_success(self, mock_run):
        """Test successful vtysh command execution."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"key": "value"}',
            stderr=""
        )

        collector = TelemetryCollector(routers=["spine1"])
        result = collector._exec_vtysh("spine1", "show ip ospf neighbor json")

        assert result == {"key": "value"}
        mock_run.assert_called_once()

    @patch('telemetry.collector.subprocess.run')
    def test_exec_vtysh_failure(self, mock_run):
        """Test vtysh command failure handling."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="Error"
        )

        collector = TelemetryCollector(routers=["spine1"])
        result = collector._exec_vtysh("spine1", "show ip ospf neighbor json")

        assert result is None

    def test_parse_neighbors(self):
        """Test neighbor JSON parsing."""
        collector = TelemetryCollector()

        neighbor_data = {
            "neighbors": {
                "10.0.1.1": [{
                    "priority": 1,
                    "nbrState": "Full",
                    "deadTimeMsecs": 35000,
                    "ifaceAddress": "10.1.1.1",
                    "ifaceName": "eth1"
                }]
            }
        }

        neighbors = collector._parse_neighbors(neighbor_data)

        assert len(neighbors) == 1
        assert neighbors[0].neighbor_id == "10.0.1.1"
        assert neighbors[0].state == "Full"
        assert neighbors[0].interface == "eth1"

    def test_parse_routes(self):
        """Test routing table JSON parsing."""
        collector = TelemetryCollector()

        route_data = {
            "10.0.1.0/24": [{
                "prefix": "10.0.1.0",
                "prefixLen": 24,
                "protocol": "ospf",
                "distance": 110,
                "metric": 20,
                "nexthops": [{
                    "ip": "10.1.1.1",
                    "interfaceName": "eth1",
                    "active": True
                }]
            }]
        }

        routing_table = collector._parse_routes(route_data)

        assert "10.0.1.0/24" in routing_table.routes
        assert len(routing_table.routes["10.0.1.0/24"]) == 1
        assert routing_table.routes["10.0.1.0/24"][0].protocol == "ospf"

    def test_parse_interfaces(self):
        """Test interface JSON parsing."""
        collector = TelemetryCollector()

        interface_data = {
            "eth1": {
                "administrativeStatus": "up",
                "linkStatus": "up",
                "mtu": 1500,
                "rxPackets": 1000,
                "rxErrors": 5,
                "txPackets": 1000,
                "txErrors": 5
            }
        }

        interfaces = collector._parse_interfaces(interface_data)

        assert "eth1" in interfaces
        assert interfaces["eth1"].link_status == "up"
        assert interfaces["eth1"].counters.rx_packets == 1000
        assert interfaces["eth1"].counters.error_rate == 0.5  # 10/2000 * 100

    def test_parse_lsdb(self):
        """Test LSDB JSON parsing."""
        collector = TelemetryCollector()

        lsdb_data = {
            "areas": {
                "0.0.0.0": {
                    "routerLinkStates": [{
                        "lsId": "10.0.0.1",
                        "advertisingRouter": "10.0.0.1",
                        "lsAge": 100,
                        "sequenceNumber": "0x80000005",
                        "checksum": "0x1234",
                        "numOfRouterLinks": 4
                    }]
                }
            }
        }

        lsdb = collector._parse_lsdb(lsdb_data)

        assert lsdb.area_id == "0.0.0.0"
        assert len(lsdb.router_lsas) == 1
        assert lsdb.router_lsas[0].lsa_id == "10.0.0.1"
        assert lsdb.router_lsas[0].link_count == 4


class TestSnapshotDiff:
    """Tests for snapshot diffing."""

    def test_diff_detects_lost_neighbor(self):
        """Test that diff detects lost OSPF neighbor."""
        from telemetry.snapshot import SnapshotDiff

        before = NetworkSnapshot(
            snapshot_id="before",
            routers={
                "spine1": RouterTelemetry(
                    router_name="spine1",
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
                    ]
                )
            }
        )

        after = NetworkSnapshot(
            snapshot_id="after",
            routers={
                "spine1": RouterTelemetry(
                    router_name="spine1",
                    neighbors=[
                        OSPFNeighbor(
                            neighbor_id="10.0.1.2",
                            state="Full",
                            address="10.1.1.3",
                            interface="eth2"
                        ),
                    ]
                )
            }
        )

        diff = SnapshotDiff(before, after)
        lost = diff.get_lost_adjacencies()

        assert len(lost) == 1
        assert lost[0]["neighbor_id"] == "10.0.1.1"
        assert lost[0]["router"] == "spine1"

    def test_diff_detects_interface_down(self):
        """Test that diff detects interface going down."""
        from telemetry.snapshot import SnapshotDiff

        before = NetworkSnapshot(
            snapshot_id="before",
            routers={
                "spine1": RouterTelemetry(
                    router_name="spine1",
                    interfaces={
                        "eth1": Interface(
                            name="eth1",
                            link_status="up"
                        )
                    }
                )
            }
        )

        after = NetworkSnapshot(
            snapshot_id="after",
            routers={
                "spine1": RouterTelemetry(
                    router_name="spine1",
                    interfaces={
                        "eth1": Interface(
                            name="eth1",
                            link_status="down"
                        )
                    }
                )
            }
        )

        diff = SnapshotDiff(before, after)
        changes = diff.get_link_status_changes()

        assert len(changes) == 1
        assert changes[0]["interface"] == "eth1"
        assert changes[0]["old_status"] == "up"
        assert changes[0]["new_status"] == "down"
