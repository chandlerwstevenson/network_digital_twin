#!/usr/bin/env python3
"""
Telemetry Collector for FRRouting containers.

Polls vtysh commands on each FRR container to collect OSPF telemetry:
- OSPF LSDB (Link State Database)
- OSPF Neighbors
- IP Routing Table
- Interface statistics

Usage:
    python collector.py --once           # Single collection
    python collector.py --interval 2     # Poll every 2 seconds
    python collector.py --output /path/to/snapshots  # Custom output directory
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from telemetry.schemas import (
    Interface,
    InterfaceCounters,
    NetworkSnapshot,
    OSPFLSDB,
    OSPFNeighbor,
    Route,
    RouteNexthop,
    RouterLSA,
    RouterTelemetry,
    RoutingTable,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Container name prefix for Containerlab
CONTAINER_PREFIX = "clab-sdn-fault-diagnosis"

# Default routers to poll
DEFAULT_ROUTERS = [
    "spine1", "spine2", "spine3", "spine4",
    "leaf1", "leaf2", "leaf3", "leaf4"
]

# vtysh commands to execute
VTYSH_COMMANDS = {
    "lsdb": "show ip ospf database json",
    "neighbors": "show ip ospf neighbor json",
    "routes": "show ip route json",
    "interfaces": "show interface json"
}


class TelemetryCollector:
    """Collects telemetry from FRRouting containers."""

    def __init__(
        self,
        routers: list[str] = None,
        container_prefix: str = CONTAINER_PREFIX,
        output_dir: Optional[Path] = None
    ):
        """
        Initialize the telemetry collector.

        Args:
            routers: List of router names to poll
            container_prefix: Containerlab container name prefix
            output_dir: Directory to save snapshots (optional)
        """
        self.routers = routers or DEFAULT_ROUTERS
        self.container_prefix = container_prefix
        self.output_dir = output_dir
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)

    def _get_container_name(self, router: str) -> str:
        """Get the full Docker container name for a router."""
        return f"{self.container_prefix}-{router}"

    def _exec_vtysh(self, router: str, command: str) -> Optional[dict]:
        """
        Execute a vtysh command on a router container via OrbStack VM.

        Args:
            router: Router name
            command: vtysh command to execute

        Returns:
            Parsed JSON output or None on error
        """
        container_name = self._get_container_name(router)
        # Use OrbStack to run docker exec in the sdn-lab VM
        full_command = [
            "orb", "-m", "sdn-lab", "sudo", "docker", "exec",
            container_name, "vtysh", "-c", command
        ]

        try:
            result = subprocess.run(
                full_command,
                capture_output=True,
                text=True,
                timeout=15  # Slightly longer timeout for OrbStack overhead
            )

            if result.returncode != 0:
                logger.warning(
                    f"vtysh command failed on {router}: {result.stderr}"
                )
                return None

            # Parse JSON output
            output = result.stdout.strip()
            if not output:
                return {}

            return json.loads(output)

        except subprocess.TimeoutExpired:
            logger.error(f"Timeout executing vtysh on {router}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON from {router}: {e}")
            logger.debug(f"Raw output: {result.stdout}")
            return None
        except Exception as e:
            logger.error(f"Error executing vtysh on {router}: {e}")
            return None

    def _parse_lsdb(self, data: dict) -> OSPFLSDB:
        """Parse OSPF LSDB JSON into schema."""
        lsdb = OSPFLSDB()

        if not data:
            return lsdb

        # Navigate to the area data
        areas = data.get("areas", {})
        for area_id, area_data in areas.items():
            lsdb.area_id = area_id

            # Parse Router LSAs
            router_lsas = area_data.get("routerLinkStates", [])
            for lsa in router_lsas:
                router_lsa = RouterLSA(
                    lsa_id=lsa.get("lsId", ""),
                    advertising_router=lsa.get("advertisingRouter", ""),
                    lsa_age=lsa.get("lsAge", 0),
                    sequence_number=lsa.get("sequenceNumber", "0x80000001"),
                    checksum=lsa.get("checksum", "0x0000"),
                    link_count=lsa.get("numOfRouterLinks", 0),
                    links=lsa.get("routerLinks", [])
                )
                lsdb.router_lsas.append(router_lsa)

            # Parse Network LSAs
            network_lsas = area_data.get("networkLinkStates", [])
            for lsa in network_lsas:
                network_lsa = NetworkLSA(
                    lsa_id=lsa.get("lsId", ""),
                    advertising_router=lsa.get("advertisingRouter", ""),
                    lsa_age=lsa.get("lsAge", 0),
                    sequence_number=lsa.get("sequenceNumber", "0x80000001"),
                    network_mask=lsa.get("networkMask", "255.255.255.0"),
                    attached_routers=lsa.get("attachedRouters", [])
                )
                lsdb.network_lsas.append(network_lsa)

        return lsdb

    def _parse_neighbors(self, data: dict) -> list[OSPFNeighbor]:
        """Parse OSPF neighbor JSON into schema."""
        neighbors = []

        if not data:
            return neighbors

        # Handle different FRR output formats
        neighbor_data = data.get("neighbors", data)
        if isinstance(neighbor_data, dict):
            for neighbor_id, info in neighbor_data.items():
                if isinstance(info, list):
                    for entry in info:
                        neighbor = self._parse_single_neighbor(neighbor_id, entry)
                        if neighbor:
                            neighbors.append(neighbor)
                elif isinstance(info, dict):
                    neighbor = self._parse_single_neighbor(neighbor_id, info)
                    if neighbor:
                        neighbors.append(neighbor)

        return neighbors

    def _parse_single_neighbor(
        self,
        neighbor_id: str,
        info: dict
    ) -> Optional[OSPFNeighbor]:
        """Parse a single neighbor entry."""
        try:
            return OSPFNeighbor(
                neighbor_id=neighbor_id,
                priority=info.get("priority", 1),
                state=info.get("nbrState", info.get("state", "Unknown")),
                dead_time_msec=info.get("deadTimeMsecs", 0),
                address=info.get("ifaceAddress", info.get("address", "")),
                interface=info.get("ifaceName", info.get("interface", "")),
                retransmit_counter=info.get("retransmitCounter", 0),
                request_counter=info.get("requestCounter", 0),
                db_summary_counter=info.get("dbSummaryCounter", 0)
            )
        except Exception as e:
            logger.warning(f"Failed to parse neighbor {neighbor_id}: {e}")
            return None

    def _parse_routes(self, data: dict) -> RoutingTable:
        """Parse IP routing table JSON into schema."""
        routing_table = RoutingTable()

        if not data:
            return routing_table

        for prefix, route_list in data.items():
            if not isinstance(route_list, list):
                continue

            routes = []
            for route_entry in route_list:
                nexthops = []
                for nh in route_entry.get("nexthops", []):
                    nexthop = RouteNexthop(
                        ip=nh.get("ip", "0.0.0.0"),
                        interface=nh.get("interfaceName", ""),
                        active=nh.get("active", True),
                        directly_connected=nh.get("directlyConnected", False)
                    )
                    nexthops.append(nexthop)

                route = Route(
                    prefix=prefix.split("/")[0] if "/" in prefix else prefix,
                    prefix_len=int(prefix.split("/")[1]) if "/" in prefix else 32,
                    protocol=route_entry.get("protocol", "unknown"),
                    distance=route_entry.get("distance", 0),
                    metric=route_entry.get("metric", 0),
                    nexthops=nexthops,
                    uptime=route_entry.get("uptime", "00:00:00"),
                    selected=route_entry.get("selected", True),
                    installed=route_entry.get("installed", True)
                )
                routes.append(route)

            routing_table.routes[prefix] = routes

        return routing_table

    def _parse_interfaces(self, data: dict) -> dict[str, Interface]:
        """Parse interface JSON into schema."""
        interfaces = {}

        if not data:
            return interfaces

        for iface_name, iface_data in data.items():
            if not isinstance(iface_data, dict):
                continue

            # Parse counters
            counters = InterfaceCounters(
                rx_packets=iface_data.get("rxPackets", 0),
                rx_bytes=iface_data.get("rxBytes", 0),
                rx_errors=iface_data.get("rxErrors", 0),
                rx_dropped=iface_data.get("rxDropped", 0),
                tx_packets=iface_data.get("txPackets", 0),
                tx_bytes=iface_data.get("txBytes", 0),
                tx_errors=iface_data.get("txErrors", 0),
                tx_dropped=iface_data.get("txDropped", 0)
            )

            # Parse IP addresses
            ip_addresses = []
            for addr_info in iface_data.get("ipAddresses", []):
                if isinstance(addr_info, dict):
                    ip_addresses.append(addr_info.get("address", ""))
                elif isinstance(addr_info, str):
                    ip_addresses.append(addr_info)

            interface = Interface(
                name=iface_name,
                status=iface_data.get("administrativeStatus", "up"),
                link_status=iface_data.get("linkStatus", iface_data.get("operationalStatus", "up")),
                mtu=iface_data.get("mtu", 1500),
                ip_addresses=ip_addresses,
                counters=counters,
                speed=iface_data.get("speed")
            )
            interfaces[iface_name] = interface

        return interfaces

    def collect_router_telemetry(self, router: str) -> Optional[RouterTelemetry]:
        """
        Collect complete telemetry from a single router.

        Args:
            router: Router name

        Returns:
            RouterTelemetry object or None on failure
        """
        logger.debug(f"Collecting telemetry from {router}")

        # Collect all data
        lsdb_data = self._exec_vtysh(router, VTYSH_COMMANDS["lsdb"])
        neighbor_data = self._exec_vtysh(router, VTYSH_COMMANDS["neighbors"])
        route_data = self._exec_vtysh(router, VTYSH_COMMANDS["routes"])
        interface_data = self._exec_vtysh(router, VTYSH_COMMANDS["interfaces"])

        # Check if we got any data
        if all(d is None for d in [lsdb_data, neighbor_data, route_data, interface_data]):
            logger.error(f"Failed to collect any telemetry from {router}")
            return None

        # Parse into schema
        telemetry = RouterTelemetry(
            router_name=router,
            timestamp=datetime.utcnow(),
            lsdb=self._parse_lsdb(lsdb_data or {}),
            neighbors=self._parse_neighbors(neighbor_data or {}),
            routing_table=self._parse_routes(route_data or {}),
            interfaces=self._parse_interfaces(interface_data or {})
        )

        # Extract router ID from LSDB if available
        if telemetry.lsdb.router_lsas:
            for lsa in telemetry.lsdb.router_lsas:
                if lsa.advertising_router:
                    # Find the LSA from this router
                    if any(
                        n.neighbor_id != lsa.advertising_router
                        for n in telemetry.neighbors
                    ):
                        telemetry.router_id = lsa.advertising_router
                        break

        return telemetry

    def collect_snapshot(self) -> NetworkSnapshot:
        """
        Collect a complete network state snapshot.

        Returns:
            NetworkSnapshot containing telemetry from all routers
        """
        start_time = time.time()
        snapshot_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")

        logger.info(f"Starting network snapshot collection: {snapshot_id}")

        snapshot = NetworkSnapshot(
            snapshot_id=snapshot_id,
            timestamp=datetime.utcnow()
        )

        for router in self.routers:
            telemetry = self.collect_router_telemetry(router)
            if telemetry:
                snapshot.routers[router] = telemetry
            else:
                logger.warning(f"Missing telemetry for {router}")

        elapsed_ms = int((time.time() - start_time) * 1000)
        snapshot.collection_duration_ms = elapsed_ms

        logger.info(
            f"Snapshot {snapshot_id} collected in {elapsed_ms}ms "
            f"({len(snapshot.routers)}/{len(self.routers)} routers)"
        )

        return snapshot

    def save_snapshot(self, snapshot: NetworkSnapshot) -> Path:
        """
        Save a snapshot to disk.

        Args:
            snapshot: NetworkSnapshot to save

        Returns:
            Path to saved file
        """
        if not self.output_dir:
            self.output_dir = Path("./snapshots")
            self.output_dir.mkdir(parents=True, exist_ok=True)

        filename = f"snapshot_{snapshot.snapshot_id}.json"
        filepath = self.output_dir / filename

        with open(filepath, "w") as f:
            f.write(snapshot.model_dump_json(indent=2))

        logger.info(f"Saved snapshot to {filepath}")
        return filepath

    def run_polling(self, interval: float = 2.0, max_snapshots: int = None):
        """
        Run continuous polling.

        Args:
            interval: Polling interval in seconds
            max_snapshots: Maximum number of snapshots (None for infinite)
        """
        count = 0
        try:
            while True:
                snapshot = self.collect_snapshot()
                self.save_snapshot(snapshot)
                count += 1

                if max_snapshots and count >= max_snapshots:
                    logger.info(f"Reached max snapshots ({max_snapshots})")
                    break

                time.sleep(interval)

        except KeyboardInterrupt:
            logger.info("Polling stopped by user")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Collect OSPF telemetry from FRRouting containers"
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Collect a single snapshot and exit"
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="Polling interval in seconds (default: 2.0)"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("./snapshots"),
        help="Output directory for snapshots"
    )
    parser.add_argument(
        "--routers",
        nargs="+",
        default=DEFAULT_ROUTERS,
        help="List of routers to poll"
    )
    parser.add_argument(
        "--prefix",
        default=CONTAINER_PREFIX,
        help="Containerlab container name prefix"
    )
    parser.add_argument(
        "--max-snapshots",
        type=int,
        default=None,
        help="Maximum number of snapshots to collect"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    collector = TelemetryCollector(
        routers=args.routers,
        container_prefix=args.prefix,
        output_dir=args.output
    )

    if args.once:
        snapshot = collector.collect_snapshot()
        filepath = collector.save_snapshot(snapshot)
        print(f"Snapshot saved to: {filepath}")
        print(f"Routers collected: {len(snapshot.routers)}")
        print(f"Total adjacencies: {snapshot.total_neighbors}")
        print(f"Full adjacencies: {snapshot.total_full_adjacencies}")
    else:
        print(f"Starting telemetry polling (interval: {args.interval}s)")
        print(f"Output directory: {args.output}")
        print("Press Ctrl+C to stop")
        collector.run_polling(
            interval=args.interval,
            max_snapshots=args.max_snapshots
        )


if __name__ == "__main__":
    main()
