#!/usr/bin/env python3
"""
Snapshot utilities for network state management.

Provides functions for:
- Loading and saving snapshots
- Comparing snapshots for diffs
- Extracting specific data from snapshots
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from telemetry.schemas import NetworkSnapshot, RouterTelemetry, RouterLSA

logger = logging.getLogger(__name__)


class SnapshotManager:
    """Manages network state snapshots."""

    def __init__(self, storage_dir: Path = None):
        """
        Initialize the snapshot manager.

        Args:
            storage_dir: Directory for storing/loading snapshots
        """
        self.storage_dir = storage_dir or Path("./snapshots")
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, NetworkSnapshot] = {}

    def save(self, snapshot: NetworkSnapshot) -> Path:
        """
        Save a snapshot to disk.

        Args:
            snapshot: NetworkSnapshot to save

        Returns:
            Path to saved file
        """
        filename = f"snapshot_{snapshot.snapshot_id}.json"
        filepath = self.storage_dir / filename

        with open(filepath, "w") as f:
            f.write(snapshot.model_dump_json(indent=2))

        self._cache[snapshot.snapshot_id] = snapshot
        logger.debug(f"Saved snapshot {snapshot.snapshot_id}")
        return filepath

    def load(self, snapshot_id: str) -> Optional[NetworkSnapshot]:
        """
        Load a snapshot from disk.

        Args:
            snapshot_id: Snapshot identifier

        Returns:
            NetworkSnapshot or None if not found
        """
        # Check cache first
        if snapshot_id in self._cache:
            return self._cache[snapshot_id]

        filename = f"snapshot_{snapshot_id}.json"
        filepath = self.storage_dir / filename

        if not filepath.exists():
            logger.warning(f"Snapshot file not found: {filepath}")
            return None

        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            snapshot = NetworkSnapshot.model_validate(data)
            self._cache[snapshot_id] = snapshot
            return snapshot
        except Exception as e:
            logger.error(f"Failed to load snapshot {snapshot_id}: {e}")
            return None

    def load_latest(self) -> Optional[NetworkSnapshot]:
        """
        Load the most recent snapshot.

        Returns:
            Most recent NetworkSnapshot or None if none exist
        """
        files = sorted(self.storage_dir.glob("snapshot_*.json"), reverse=True)
        if not files:
            return None

        # Extract snapshot ID from filename
        latest_file = files[0]
        snapshot_id = latest_file.stem.replace("snapshot_", "")
        return self.load(snapshot_id)

    def list_snapshots(self) -> list[str]:
        """
        List all available snapshot IDs.

        Returns:
            List of snapshot IDs sorted by time (newest first)
        """
        files = sorted(self.storage_dir.glob("snapshot_*.json"), reverse=True)
        return [f.stem.replace("snapshot_", "") for f in files]

    def clear_cache(self):
        """Clear the in-memory cache."""
        self._cache.clear()


class SnapshotDiff:
    """Computes differences between two network snapshots."""

    def __init__(self, before: NetworkSnapshot, after: NetworkSnapshot):
        """
        Initialize diff between two snapshots.

        Args:
            before: Earlier snapshot
            after: Later snapshot
        """
        self.before = before
        self.after = after
        self._diff: Optional[dict] = None

    def compute(self) -> dict[str, Any]:
        """
        Compute the full diff between snapshots.

        Returns:
            Dict containing all differences
        """
        if self._diff is not None:
            return self._diff

        self._diff = {
            "snapshot_before": self.before.snapshot_id,
            "snapshot_after": self.after.snapshot_id,
            "time_delta_ms": int(
                (self.after.timestamp - self.before.timestamp).total_seconds() * 1000
            ),
            "routers_added": [],
            "routers_removed": [],
            "router_diffs": {},
        }

        before_routers = set(self.before.routers.keys())
        after_routers = set(self.after.routers.keys())

        self._diff["routers_added"] = list(after_routers - before_routers)
        self._diff["routers_removed"] = list(before_routers - after_routers)

        # Compute per-router diffs
        common_routers = before_routers & after_routers
        for router in common_routers:
            router_diff = self._diff_router(
                self.before.routers[router],
                self.after.routers[router]
            )
            if router_diff:
                self._diff["router_diffs"][router] = router_diff

        return self._diff

    def _diff_router(
        self,
        before: RouterTelemetry,
        after: RouterTelemetry
    ) -> Optional[dict]:
        """
        Compute diff for a single router.

        Returns:
            Dict with differences or None if identical
        """
        diff = {
            "lsdb_changes": self._diff_lsdb(before, after),
            "neighbor_changes": self._diff_neighbors(before, after),
            "route_changes": self._diff_routes(before, after),
            "interface_changes": self._diff_interfaces(before, after),
        }

        # Check if any changes
        if all(not v for v in diff.values()):
            return None

        return diff

    def _diff_lsdb(
        self,
        before: RouterTelemetry,
        after: RouterTelemetry
    ) -> dict:
        """Diff LSDB between two snapshots of a router."""
        changes = {
            "router_lsas_added": [],
            "router_lsas_removed": [],
            "router_lsas_modified": [],
        }

        # Create lookup by LSA ID
        before_lsas = {lsa.lsa_id: lsa for lsa in before.lsdb.router_lsas}
        after_lsas = {lsa.lsa_id: lsa for lsa in after.lsdb.router_lsas}

        before_ids = set(before_lsas.keys())
        after_ids = set(after_lsas.keys())

        # Added LSAs
        for lsa_id in after_ids - before_ids:
            changes["router_lsas_added"].append(lsa_id)

        # Removed LSAs
        for lsa_id in before_ids - after_ids:
            changes["router_lsas_removed"].append(lsa_id)

        # Modified LSAs (sequence number changed)
        for lsa_id in before_ids & after_ids:
            if before_lsas[lsa_id].sequence_number != after_lsas[lsa_id].sequence_number:
                changes["router_lsas_modified"].append({
                    "lsa_id": lsa_id,
                    "old_seq": before_lsas[lsa_id].sequence_number,
                    "new_seq": after_lsas[lsa_id].sequence_number,
                    "old_link_count": before_lsas[lsa_id].link_count,
                    "new_link_count": after_lsas[lsa_id].link_count,
                })

        # Return empty dict if no changes
        if not any(changes.values()):
            return {}

        return changes

    def _diff_neighbors(
        self,
        before: RouterTelemetry,
        after: RouterTelemetry
    ) -> dict:
        """Diff OSPF neighbors between two snapshots."""
        changes = {
            "neighbors_added": [],
            "neighbors_removed": [],
            "state_changes": [],
        }

        before_neighbors = {n.neighbor_id: n for n in before.neighbors}
        after_neighbors = {n.neighbor_id: n for n in after.neighbors}

        before_ids = set(before_neighbors.keys())
        after_ids = set(after_neighbors.keys())

        # Added neighbors
        for nbr_id in after_ids - before_ids:
            nbr = after_neighbors[nbr_id]
            changes["neighbors_added"].append({
                "neighbor_id": nbr_id,
                "state": nbr.state,
                "interface": nbr.interface,
            })

        # Removed neighbors
        for nbr_id in before_ids - after_ids:
            nbr = before_neighbors[nbr_id]
            changes["neighbors_removed"].append({
                "neighbor_id": nbr_id,
                "state": nbr.state,
                "interface": nbr.interface,
            })

        # State changes
        for nbr_id in before_ids & after_ids:
            if before_neighbors[nbr_id].state != after_neighbors[nbr_id].state:
                changes["state_changes"].append({
                    "neighbor_id": nbr_id,
                    "old_state": before_neighbors[nbr_id].state,
                    "new_state": after_neighbors[nbr_id].state,
                    "interface": after_neighbors[nbr_id].interface,
                })

        if not any(changes.values()):
            return {}

        return changes

    def _diff_routes(
        self,
        before: RouterTelemetry,
        after: RouterTelemetry
    ) -> dict:
        """Diff routing tables between two snapshots."""
        changes = {
            "routes_added": [],
            "routes_removed": [],
            "routes_modified": [],
        }

        before_routes = set(before.routing_table.routes.keys())
        after_routes = set(after.routing_table.routes.keys())

        # Added routes
        for prefix in after_routes - before_routes:
            changes["routes_added"].append(prefix)

        # Removed routes
        for prefix in before_routes - after_routes:
            changes["routes_removed"].append(prefix)

        # Modified routes (check nexthops)
        for prefix in before_routes & after_routes:
            before_nhs = set(
                f"{nh.ip}:{nh.interface}"
                for route in before.routing_table.routes[prefix]
                for nh in route.nexthops
            )
            after_nhs = set(
                f"{nh.ip}:{nh.interface}"
                for route in after.routing_table.routes[prefix]
                for nh in route.nexthops
            )
            if before_nhs != after_nhs:
                changes["routes_modified"].append({
                    "prefix": prefix,
                    "nexthops_added": list(after_nhs - before_nhs),
                    "nexthops_removed": list(before_nhs - after_nhs),
                })

        if not any(changes.values()):
            return {}

        return changes

    def _diff_interfaces(
        self,
        before: RouterTelemetry,
        after: RouterTelemetry
    ) -> dict:
        """Diff interfaces between two snapshots."""
        changes = {
            "interfaces_added": [],
            "interfaces_removed": [],
            "status_changes": [],
            "counter_anomalies": [],
        }

        before_ifaces = set(before.interfaces.keys())
        after_ifaces = set(after.interfaces.keys())

        # Added/removed interfaces
        changes["interfaces_added"] = list(after_ifaces - before_ifaces)
        changes["interfaces_removed"] = list(before_ifaces - after_ifaces)

        # Status and counter changes
        for iface in before_ifaces & after_ifaces:
            before_if = before.interfaces[iface]
            after_if = after.interfaces[iface]

            # Link status change
            if before_if.link_status != after_if.link_status:
                changes["status_changes"].append({
                    "interface": iface,
                    "old_status": before_if.link_status,
                    "new_status": after_if.link_status,
                })

            # Check for error/drop rate anomalies
            if (
                after_if.counters.error_rate > 1.0 or
                after_if.counters.drop_rate > 1.0
            ):
                changes["counter_anomalies"].append({
                    "interface": iface,
                    "error_rate": after_if.counters.error_rate,
                    "drop_rate": after_if.counters.drop_rate,
                })

        if not any(changes.values()):
            return {}

        return changes

    @property
    def has_changes(self) -> bool:
        """Check if there are any differences."""
        diff = self.compute()
        return bool(
            diff["routers_added"] or
            diff["routers_removed"] or
            diff["router_diffs"]
        )

    def get_affected_routers(self) -> set[str]:
        """Get set of routers with changes."""
        diff = self.compute()
        affected = set(diff["routers_added"])
        affected.update(diff["routers_removed"])
        affected.update(diff["router_diffs"].keys())
        return affected

    def get_lost_adjacencies(self) -> list[dict]:
        """Get list of lost OSPF adjacencies."""
        diff = self.compute()
        lost = []

        for router, router_diff in diff["router_diffs"].items():
            neighbor_changes = router_diff.get("neighbor_changes", {})
            for removed in neighbor_changes.get("neighbors_removed", []):
                lost.append({
                    "router": router,
                    "neighbor_id": removed["neighbor_id"],
                    "interface": removed["interface"],
                })

        return lost

    def get_link_status_changes(self) -> list[dict]:
        """Get list of interface status changes."""
        diff = self.compute()
        changes = []

        for router, router_diff in diff["router_diffs"].items():
            iface_changes = router_diff.get("interface_changes", {})
            for change in iface_changes.get("status_changes", []):
                changes.append({
                    "router": router,
                    "interface": change["interface"],
                    "old_status": change["old_status"],
                    "new_status": change["new_status"],
                })

        return changes


def load_snapshot_from_file(filepath: Path) -> Optional[NetworkSnapshot]:
    """
    Load a snapshot directly from a file path.

    Args:
        filepath: Path to snapshot JSON file

    Returns:
        NetworkSnapshot or None on error
    """
    try:
        with open(filepath, "r") as f:
            data = json.load(f)
        return NetworkSnapshot.model_validate(data)
    except Exception as e:
        logger.error(f"Failed to load snapshot from {filepath}: {e}")
        return None


def create_snapshot_from_dict(data: dict) -> NetworkSnapshot:
    """
    Create a NetworkSnapshot from a raw dictionary.

    Args:
        data: Dict containing snapshot data

    Returns:
        NetworkSnapshot instance
    """
    return NetworkSnapshot.model_validate(data)


def compare_snapshots(
    before: NetworkSnapshot,
    after: NetworkSnapshot
) -> SnapshotDiff:
    """
    Compare two snapshots and return their differences.

    Args:
        before: Earlier snapshot
        after: Later snapshot

    Returns:
        SnapshotDiff instance
    """
    return SnapshotDiff(before, after)
