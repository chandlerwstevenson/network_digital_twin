"""
Telemetry collection module for SDN fault diagnosis.

This module provides:
- schemas: Pydantic models for telemetry data structures
- collector: Polling daemon for FRRouting containers
- snapshot: Utilities for snapshot management and diffing
"""

from .schemas import (
    DiagnosisResult,
    Interface,
    InterfaceCounters,
    NetworkLSA,
    NetworkSnapshot,
    OSPFNeighbor,
    OSPFNeighborState,
    OSPFLSDB,
    Route,
    RouteNexthop,
    RouterLSA,
    RouterTelemetry,
    RoutingTable,
    TrialResult,
)
from .collector import TelemetryCollector
from .snapshot import (
    SnapshotManager,
    SnapshotDiff,
    compare_snapshots,
    load_snapshot_from_file,
)

__all__ = [
    # Schemas
    "DiagnosisResult",
    "Interface",
    "InterfaceCounters",
    "NetworkLSA",
    "NetworkSnapshot",
    "OSPFNeighbor",
    "OSPFNeighborState",
    "OSPFLSDB",
    "Route",
    "RouteNexthop",
    "RouterLSA",
    "RouterTelemetry",
    "RoutingTable",
    "TrialResult",
    # Collector
    "TelemetryCollector",
    # Snapshot utilities
    "SnapshotManager",
    "SnapshotDiff",
    "compare_snapshots",
    "load_snapshot_from_file",
]
