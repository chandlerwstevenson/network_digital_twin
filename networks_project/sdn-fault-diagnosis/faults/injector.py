#!/usr/bin/env python3
"""
Fault Injection Harness for SDN Fault Diagnosis.

Provides high-level interface for:
- Injecting faults into the network
- Managing fault lifecycle (inject -> verify -> restore)
- Running fault scenarios
- Recording fault history

Usage:
    python -m faults.injector --fault link_down --target spine1 --interface eth1
    python -m faults.injector --scenario single_link_failure
    python -m faults.injector --restore-all
"""

import argparse
import json
import logging
import random
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from .fault_types import (
    BaseFault,
    CounterAnomaly,
    FaultClass,
    FaultResult,
    FlappingLink,
    LinkFailure,
    MissingRoute,
    StaleRoute,
    create_fault,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Default topology information
SPINE_ROUTERS = ["spine1", "spine2", "spine3", "spine4"]
LEAF_ROUTERS = ["leaf1", "leaf2", "leaf3", "leaf4"]
ALL_ROUTERS = SPINE_ROUTERS + LEAF_ROUTERS

# Interface mappings (which interfaces connect to which)
SPINE_INTERFACES = ["eth1", "eth2", "eth3", "eth4"]  # Connect to leaf1-4
LEAF_SPINE_INTERFACES = ["eth1", "eth2", "eth3", "eth4"]  # Connect to spine1-4
LEAF_HOST_INTERFACES = ["eth5", "eth6"]  # Connect to hosts

# Host subnets per leaf
LEAF_HOST_SUBNETS = {
    "leaf1": "192.168.1.0/24",
    "leaf2": "192.168.2.0/24",
    "leaf3": "192.168.3.0/24",
    "leaf4": "192.168.4.0/24",
}


@dataclass
class FaultRecord:
    """Record of an injected fault."""
    fault_id: str
    fault_class: FaultClass
    container: str
    params: dict[str, Any]
    inject_time: datetime
    restore_time: Optional[datetime] = None
    inject_result: Optional[FaultResult] = None
    restore_result: Optional[FaultResult] = None
    verified: bool = False


@dataclass
class InjectorState:
    """State of the fault injector."""
    active_faults: dict[str, BaseFault] = field(default_factory=dict)
    fault_history: list[FaultRecord] = field(default_factory=list)


class FaultInjector:
    """
    Manages fault injection lifecycle.

    Tracks active faults, provides methods to inject/restore,
    and maintains history for analysis.
    """

    def __init__(self, container_prefix: str = "clab-sdn-fault-diagnosis"):
        """
        Initialize the fault injector.

        Args:
            container_prefix: Containerlab container name prefix
        """
        self.container_prefix = container_prefix
        self.state = InjectorState()
        self._fault_counter = 0

    def _generate_fault_id(self) -> str:
        """Generate unique fault ID."""
        self._fault_counter += 1
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        return f"fault_{timestamp}_{self._fault_counter:04d}"

    def inject_link_failure(
        self,
        container: str,
        interface: str
    ) -> tuple[str, FaultResult]:
        """
        Inject a link failure fault.

        Args:
            container: Router name
            interface: Interface to bring down

        Returns:
            Tuple of (fault_id, result)
        """
        fault = LinkFailure(
            container=container,
            interface=interface,
            container_prefix=self.container_prefix
        )
        return self._inject_fault(fault)

    def inject_flapping_link(
        self,
        container: str,
        interface: str,
        period_sec: float = 5.0,
        count: int = 3
    ) -> tuple[str, FaultResult]:
        """
        Inject a flapping link fault.

        Args:
            container: Router name
            interface: Interface to flap
            period_sec: Time between state changes
            count: Number of up/down cycles

        Returns:
            Tuple of (fault_id, result)
        """
        fault = FlappingLink(
            container=container,
            interface=interface,
            period_sec=period_sec,
            count=count,
            container_prefix=self.container_prefix
        )
        return self._inject_fault(fault)

    def inject_stale_route(
        self,
        container: str,
        prefix: str,
        nexthop: str,
        distance: int = 1
    ) -> tuple[str, FaultResult]:
        """
        Inject a stale route fault.

        Args:
            container: Router name
            prefix: Destination prefix
            nexthop: Incorrect next-hop
            distance: Administrative distance

        Returns:
            Tuple of (fault_id, result)
        """
        fault = StaleRoute(
            container=container,
            prefix=prefix,
            nexthop=nexthop,
            distance=distance,
            container_prefix=self.container_prefix
        )
        return self._inject_fault(fault)

    def inject_missing_route(
        self,
        container: str,
        prefix: str,
        area: str = "0"
    ) -> tuple[str, FaultResult]:
        """
        Inject a missing route fault.

        Args:
            container: Router name
            prefix: Network prefix to withdraw
            area: OSPF area

        Returns:
            Tuple of (fault_id, result)
        """
        fault = MissingRoute(
            container=container,
            prefix=prefix,
            area=area,
            container_prefix=self.container_prefix
        )
        return self._inject_fault(fault)

    def inject_counter_anomaly(
        self,
        container: str,
        interface: str,
        loss_pct: float = 5.0,
        corrupt_pct: float = 0.0
    ) -> tuple[str, FaultResult]:
        """
        Inject a counter anomaly fault.

        Args:
            container: Router name
            interface: Interface to affect
            loss_pct: Packet loss percentage
            corrupt_pct: Packet corruption percentage

        Returns:
            Tuple of (fault_id, result)
        """
        fault = CounterAnomaly(
            container=container,
            interface=interface,
            loss_pct=loss_pct,
            corrupt_pct=corrupt_pct,
            container_prefix=self.container_prefix
        )
        return self._inject_fault(fault)

    def _inject_fault(self, fault: BaseFault) -> tuple[str, FaultResult]:
        """
        Internal method to inject a fault and track it.

        Args:
            fault: Fault instance to inject

        Returns:
            Tuple of (fault_id, result)
        """
        fault_id = self._generate_fault_id()

        # Create record
        record = FaultRecord(
            fault_id=fault_id,
            fault_class=fault.fault_class,
            container=fault.container,
            params=fault.to_dict(),
            inject_time=datetime.utcnow()
        )

        # Inject
        result = fault.inject()
        record.inject_result = result

        if result.success:
            # Verify
            time.sleep(0.5)  # Brief delay for state to stabilize
            record.verified = fault.verify()

            # Track active fault
            self.state.active_faults[fault_id] = fault

            logger.info(
                f"Injected fault {fault_id}: {fault.fault_class.value} "
                f"on {fault.container} (verified: {record.verified})"
            )
        else:
            logger.error(f"Failed to inject fault: {result.message}")

        self.state.fault_history.append(record)
        return fault_id, result

    def restore_fault(self, fault_id: str) -> FaultResult:
        """
        Restore a specific fault.

        Args:
            fault_id: ID of fault to restore

        Returns:
            FaultResult indicating success/failure
        """
        if fault_id not in self.state.active_faults:
            return FaultResult(
                success=False,
                message=f"Fault {fault_id} not found or already restored"
            )

        fault = self.state.active_faults[fault_id]
        result = fault.restore()

        if result.success:
            del self.state.active_faults[fault_id]

            # Update record
            for record in reversed(self.state.fault_history):
                if record.fault_id == fault_id:
                    record.restore_time = datetime.utcnow()
                    record.restore_result = result
                    break

            logger.info(f"Restored fault {fault_id}")
        else:
            logger.error(f"Failed to restore fault {fault_id}: {result.message}")

        return result

    def restore_all(self) -> list[FaultResult]:
        """
        Restore all active faults.

        Returns:
            List of restoration results
        """
        results = []
        fault_ids = list(self.state.active_faults.keys())

        for fault_id in fault_ids:
            result = self.restore_fault(fault_id)
            results.append(result)

        return results

    def get_active_faults(self) -> dict[str, dict]:
        """
        Get information about active faults.

        Returns:
            Dict mapping fault_id to fault info
        """
        return {
            fault_id: fault.to_dict()
            for fault_id, fault in self.state.active_faults.items()
        }

    def get_fault_history(self) -> list[dict]:
        """
        Get fault history as list of dicts.

        Returns:
            List of fault records as dicts
        """
        history = []
        for record in self.state.fault_history:
            entry = {
                "fault_id": record.fault_id,
                "fault_class": record.fault_class.value,
                "container": record.container,
                "params": record.params,
                "inject_time": record.inject_time.isoformat(),
                "restore_time": record.restore_time.isoformat() if record.restore_time else None,
                "verified": record.verified,
                "inject_success": record.inject_result.success if record.inject_result else None,
                "restore_success": record.restore_result.success if record.restore_result else None,
            }
            history.append(entry)
        return history

    def inject_random_fault(
        self,
        fault_class: Optional[FaultClass] = None
    ) -> tuple[str, FaultResult, dict]:
        """
        Inject a random fault of the specified class (or any class).

        Args:
            fault_class: Specific fault class, or None for random

        Returns:
            Tuple of (fault_id, result, ground_truth)
        """
        if fault_class is None:
            fault_class = random.choice(list(FaultClass))

        ground_truth = {"fault_class": fault_class.value}

        if fault_class == FaultClass.LINK_FAILURE:
            # Random spine-leaf link
            if random.random() < 0.5:
                container = random.choice(SPINE_ROUTERS)
                interface = random.choice(SPINE_INTERFACES)
            else:
                container = random.choice(LEAF_ROUTERS)
                interface = random.choice(LEAF_SPINE_INTERFACES)

            ground_truth.update({
                "container": container,
                "interface": interface,
                "location": f"{container}:{interface}"
            })

            fault_id, result = self.inject_link_failure(container, interface)

        elif fault_class == FaultClass.FLAPPING_LINK:
            container = random.choice(ALL_ROUTERS)
            if container in SPINE_ROUTERS:
                interface = random.choice(SPINE_INTERFACES)
            else:
                interface = random.choice(LEAF_SPINE_INTERFACES)

            ground_truth.update({
                "container": container,
                "interface": interface,
                "location": f"{container}:{interface}",
                "period_sec": 5.0,
                "count": 3
            })

            fault_id, result = self.inject_flapping_link(
                container, interface,
                period_sec=5.0,
                count=3
            )

        elif fault_class == FaultClass.STALE_ROUTE:
            # Pick a random leaf and inject wrong route to another leaf's subnet
            container = random.choice(LEAF_ROUTERS)
            other_leafs = [l for l in LEAF_ROUTERS if l != container]
            target_leaf = random.choice(other_leafs)
            prefix = LEAF_HOST_SUBNETS[target_leaf]

            # Use a random spine loopback as incorrect nexthop
            nexthop = f"10.0.0.{random.randint(1, 4)}"

            ground_truth.update({
                "container": container,
                "prefix": prefix,
                "nexthop": nexthop,
                "location": f"{container}:{prefix}"
            })

            fault_id, result = self.inject_stale_route(
                container, prefix, nexthop
            )

        elif fault_class == FaultClass.MISSING_ROUTE:
            # Withdraw a host subnet from a leaf
            container = random.choice(LEAF_ROUTERS)
            prefix = LEAF_HOST_SUBNETS[container]

            ground_truth.update({
                "container": container,
                "prefix": prefix,
                "location": f"{container}:{prefix}"
            })

            fault_id, result = self.inject_missing_route(container, prefix)

        elif fault_class == FaultClass.COUNTER_ANOMALY:
            container = random.choice(ALL_ROUTERS)
            if container in SPINE_ROUTERS:
                interface = random.choice(SPINE_INTERFACES)
            else:
                interface = random.choice(LEAF_SPINE_INTERFACES)

            loss_pct = random.uniform(2.0, 10.0)

            ground_truth.update({
                "container": container,
                "interface": interface,
                "location": f"{container}:{interface}",
                "loss_pct": loss_pct
            })

            fault_id, result = self.inject_counter_anomaly(
                container, interface, loss_pct=loss_pct
            )

        else:
            raise ValueError(f"Unknown fault class: {fault_class}")

        return fault_id, result, ground_truth

    def save_state(self, filepath: Path):
        """Save current state to file."""
        state_dict = {
            "active_faults": self.get_active_faults(),
            "fault_history": self.get_fault_history(),
            "timestamp": datetime.utcnow().isoformat()
        }
        with open(filepath, "w") as f:
            json.dump(state_dict, f, indent=2)

    def clear_history(self):
        """Clear fault history (does not restore active faults)."""
        self.state.fault_history.clear()


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Inject faults into the SDN network"
    )

    subparsers = parser.add_subparsers(dest="command", help="Command")

    # link_down command
    link_down = subparsers.add_parser("link_down", help="Bring a link down")
    link_down.add_argument("--target", required=True, help="Router name")
    link_down.add_argument("--interface", required=True, help="Interface name")

    # flapping command
    flapping = subparsers.add_parser("flapping", help="Create flapping link")
    flapping.add_argument("--target", required=True, help="Router name")
    flapping.add_argument("--interface", required=True, help="Interface name")
    flapping.add_argument("--period", type=float, default=5.0, help="Flap period")
    flapping.add_argument("--count", type=int, default=3, help="Flap count")

    # stale_route command
    stale = subparsers.add_parser("stale_route", help="Inject stale route")
    stale.add_argument("--target", required=True, help="Router name")
    stale.add_argument("--prefix", required=True, help="Destination prefix")
    stale.add_argument("--nexthop", required=True, help="Incorrect next-hop")

    # missing_route command
    missing = subparsers.add_parser("missing_route", help="Withdraw OSPF network")
    missing.add_argument("--target", required=True, help="Router name")
    missing.add_argument("--prefix", required=True, help="Network prefix")

    # counter_anomaly command
    counter = subparsers.add_parser("counter_anomaly", help="Inject packet loss")
    counter.add_argument("--target", required=True, help="Router name")
    counter.add_argument("--interface", required=True, help="Interface name")
    counter.add_argument("--loss", type=float, default=5.0, help="Loss percentage")

    # random command
    rand = subparsers.add_parser("random", help="Inject random fault")
    rand.add_argument(
        "--type",
        choices=[f.value for f in FaultClass],
        help="Specific fault type"
    )

    # restore command
    restore = subparsers.add_parser("restore", help="Restore a fault")
    restore.add_argument("--fault-id", help="Fault ID to restore")
    restore.add_argument("--all", action="store_true", help="Restore all faults")

    # list command
    subparsers.add_parser("list", help="List active faults")

    # Common arguments
    parser.add_argument(
        "--prefix",
        default="clab-sdn-fault-diagnosis",
        help="Container name prefix"
    )

    args = parser.parse_args()

    injector = FaultInjector(container_prefix=args.prefix)

    if args.command == "link_down":
        fault_id, result = injector.inject_link_failure(
            args.target, args.interface
        )
        print(f"Fault ID: {fault_id}")
        print(f"Success: {result.success}")
        print(f"Message: {result.message}")

    elif args.command == "flapping":
        fault_id, result = injector.inject_flapping_link(
            args.target, args.interface,
            period_sec=args.period,
            count=args.count
        )
        print(f"Fault ID: {fault_id}")
        print(f"Success: {result.success}")
        print(f"Message: {result.message}")

    elif args.command == "stale_route":
        fault_id, result = injector.inject_stale_route(
            args.target, args.prefix, args.nexthop
        )
        print(f"Fault ID: {fault_id}")
        print(f"Success: {result.success}")
        print(f"Message: {result.message}")

    elif args.command == "missing_route":
        fault_id, result = injector.inject_missing_route(
            args.target, args.prefix
        )
        print(f"Fault ID: {fault_id}")
        print(f"Success: {result.success}")
        print(f"Message: {result.message}")

    elif args.command == "counter_anomaly":
        fault_id, result = injector.inject_counter_anomaly(
            args.target, args.interface, loss_pct=args.loss
        )
        print(f"Fault ID: {fault_id}")
        print(f"Success: {result.success}")
        print(f"Message: {result.message}")

    elif args.command == "random":
        fault_class = FaultClass(args.type) if args.type else None
        fault_id, result, ground_truth = injector.inject_random_fault(fault_class)
        print(f"Fault ID: {fault_id}")
        print(f"Success: {result.success}")
        print(f"Ground Truth: {json.dumps(ground_truth, indent=2)}")

    elif args.command == "restore":
        if args.all:
            results = injector.restore_all()
            for i, result in enumerate(results):
                print(f"Restore {i+1}: {result.success} - {result.message}")
        elif args.fault_id:
            result = injector.restore_fault(args.fault_id)
            print(f"Success: {result.success}")
            print(f"Message: {result.message}")
        else:
            print("Specify --fault-id or --all")

    elif args.command == "list":
        active = injector.get_active_faults()
        if active:
            print(json.dumps(active, indent=2))
        else:
            print("No active faults")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
