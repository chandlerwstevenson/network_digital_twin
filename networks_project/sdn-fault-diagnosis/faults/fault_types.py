"""
Fault type definitions for SDN fault injection.

Defines the taxonomy of faults that can be injected into the network:
- Link failures (hard down)
- Flapping links (intermittent connectivity)
- Stale routes (incorrect routing entries)
- Missing routes (withdrawn OSPF networks)
- Counter anomalies (packet loss/errors)
"""

import logging
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Container prefix for Containerlab
CONTAINER_PREFIX = "clab-sdn-fault-diagnosis"


class FaultClass(str, Enum):
    """Classification of fault types."""
    LINK_FAILURE = "link_failure"
    FLAPPING_LINK = "flapping_link"
    STALE_ROUTE = "stale_route"
    MISSING_ROUTE = "missing_route"
    COUNTER_ANOMALY = "counter_anomaly"


@dataclass
class FaultResult:
    """Result of fault injection or restoration."""
    success: bool
    message: str
    details: dict[str, Any] = field(default_factory=dict)


class BaseFault(ABC):
    """Abstract base class for all fault types."""

    fault_class: FaultClass
    description: str = ""

    def __init__(
        self,
        container: str,
        container_prefix: str = CONTAINER_PREFIX
    ):
        """
        Initialize fault.

        Args:
            container: Router container name (e.g., 'spine1')
            container_prefix: Containerlab container name prefix
        """
        self.container = container
        self.container_prefix = container_prefix
        self._injected = False

    @property
    def full_container_name(self) -> str:
        """Get the full Docker container name."""
        return f"{self.container_prefix}-{self.container}"

    def _exec(self, command: list[str], timeout: int = 15) -> tuple[bool, str]:
        """
        Execute a command in the container via OrbStack VM.

        Args:
            command: Command to execute (without docker exec prefix)
            timeout: Command timeout in seconds

        Returns:
            Tuple of (success, output)
        """
        # Use OrbStack to run docker exec in the sdn-lab VM
        full_cmd = [
            "orb", "-m", "sdn-lab", "sudo", "docker", "exec",
            self.full_container_name
        ] + command

        try:
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            if result.returncode != 0:
                return False, result.stderr

            return True, result.stdout

        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)

    def _exec_vtysh(self, command: str) -> tuple[bool, str]:
        """Execute a vtysh command."""
        return self._exec(["vtysh", "-c", command])

    @abstractmethod
    def inject(self) -> FaultResult:
        """Inject the fault. Must be implemented by subclasses."""
        pass

    @abstractmethod
    def restore(self) -> FaultResult:
        """Restore from the fault. Must be implemented by subclasses."""
        pass

    @abstractmethod
    def verify(self) -> bool:
        """Verify the fault is active. Must be implemented by subclasses."""
        pass

    def to_dict(self) -> dict[str, Any]:
        """Serialize fault to dictionary."""
        return {
            "fault_class": self.fault_class.value,
            "container": self.container,
            "description": self.description,
            "injected": self._injected,
        }


class LinkFailure(BaseFault):
    """
    Hard link failure fault.

    Brings an interface administratively down, causing:
    - Immediate OSPF neighbor loss
    - LSDB updates (Router LSA link removal)
    - Route reconvergence
    """

    fault_class = FaultClass.LINK_FAILURE
    description = "Interface administratively down"

    def __init__(
        self,
        container: str,
        interface: str,
        container_prefix: str = CONTAINER_PREFIX
    ):
        """
        Initialize link failure fault.

        Args:
            container: Router container name
            interface: Interface to bring down (e.g., 'eth1')
            container_prefix: Container name prefix
        """
        super().__init__(container, container_prefix)
        self.interface = interface

    def inject(self) -> FaultResult:
        """Bring interface down."""
        logger.info(f"Injecting link failure: {self.container}:{self.interface}")

        success, output = self._exec(["ip", "link", "set", self.interface, "down"])

        if success:
            self._injected = True
            return FaultResult(
                success=True,
                message=f"Interface {self.interface} on {self.container} is down",
                details={"interface": self.interface, "container": self.container}
            )
        else:
            return FaultResult(
                success=False,
                message=f"Failed to bring down interface: {output}",
                details={"error": output}
            )

    def restore(self) -> FaultResult:
        """Bring interface back up."""
        logger.info(f"Restoring link: {self.container}:{self.interface}")

        success, output = self._exec(["ip", "link", "set", self.interface, "up"])

        if success:
            self._injected = False
            return FaultResult(
                success=True,
                message=f"Interface {self.interface} on {self.container} is up",
                details={"interface": self.interface, "container": self.container}
            )
        else:
            return FaultResult(
                success=False,
                message=f"Failed to bring up interface: {output}",
                details={"error": output}
            )

    def verify(self) -> bool:
        """Verify interface is down."""
        success, output = self._exec(["ip", "link", "show", self.interface])
        if not success:
            return False

        # Check if interface state contains "DOWN"
        return "state DOWN" in output or "state down" in output

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        result = super().to_dict()
        result["interface"] = self.interface
        return result


class FlappingLink(BaseFault):
    """
    Link flapping fault.

    Rapidly cycles an interface up/down, causing:
    - Repeated OSPF neighbor state changes
    - Multiple LSDB updates
    - Routing instability
    """

    fault_class = FaultClass.FLAPPING_LINK
    description = "Interface cycling up/down"

    def __init__(
        self,
        container: str,
        interface: str,
        period_sec: float = 5.0,
        count: int = 3,
        container_prefix: str = CONTAINER_PREFIX
    ):
        """
        Initialize flapping link fault.

        Args:
            container: Router container name
            interface: Interface to flap
            period_sec: Period between state changes
            count: Number of down/up cycles
            container_prefix: Container name prefix
        """
        super().__init__(container, container_prefix)
        self.interface = interface
        self.period_sec = period_sec
        self.count = count
        self._flap_count = 0

    def inject(self) -> FaultResult:
        """
        Execute link flapping sequence.

        This is a blocking operation that takes period_sec * count * 2 seconds.
        """
        logger.info(
            f"Injecting flapping link: {self.container}:{self.interface} "
            f"({self.count} cycles, {self.period_sec}s period)"
        )

        self._injected = True

        for i in range(self.count):
            # Bring down
            success, _ = self._exec(["ip", "link", "set", self.interface, "down"])
            if not success:
                return FaultResult(
                    success=False,
                    message=f"Failed to bring down interface on cycle {i+1}"
                )

            time.sleep(self.period_sec)

            # Bring up
            success, _ = self._exec(["ip", "link", "set", self.interface, "up"])
            if not success:
                return FaultResult(
                    success=False,
                    message=f"Failed to bring up interface on cycle {i+1}"
                )

            time.sleep(self.period_sec)
            self._flap_count = i + 1

        self._injected = False

        return FaultResult(
            success=True,
            message=f"Completed {self.count} flap cycles on {self.container}:{self.interface}",
            details={
                "interface": self.interface,
                "container": self.container,
                "cycles": self.count,
                "period_sec": self.period_sec
            }
        )

    def restore(self) -> FaultResult:
        """Ensure interface is up."""
        success, output = self._exec(["ip", "link", "set", self.interface, "up"])

        if success:
            self._injected = False
            return FaultResult(
                success=True,
                message=f"Interface {self.interface} is up"
            )
        else:
            return FaultResult(
                success=False,
                message=f"Failed to restore interface: {output}"
            )

    def verify(self) -> bool:
        """Verify flapping is in progress (interface might be up or down)."""
        return self._injected

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        result = super().to_dict()
        result.update({
            "interface": self.interface,
            "period_sec": self.period_sec,
            "count": self.count,
            "flap_count": self._flap_count,
        })
        return result


class StaleRoute(BaseFault):
    """
    Stale/incorrect route fault.

    Injects a static route with higher preference, causing:
    - Traffic blackholing or misdirection
    - Routing inconsistency with LSDB
    """

    fault_class = FaultClass.STALE_ROUTE
    description = "Incorrect static route injection"

    def __init__(
        self,
        container: str,
        prefix: str,
        nexthop: str,
        distance: int = 1,
        container_prefix: str = CONTAINER_PREFIX
    ):
        """
        Initialize stale route fault.

        Args:
            container: Router container name
            prefix: Destination prefix (e.g., '10.0.1.0/24')
            nexthop: Incorrect next-hop IP
            distance: Administrative distance (lower = more preferred)
            container_prefix: Container name prefix
        """
        super().__init__(container, container_prefix)
        self.prefix = prefix
        self.nexthop = nexthop
        self.distance = distance

    def inject(self) -> FaultResult:
        """Inject static route with incorrect next-hop."""
        logger.info(
            f"Injecting stale route: {self.prefix} via {self.nexthop} "
            f"on {self.container}"
        )

        # Configure static route via vtysh
        cmd = f"configure terminal\nip route {self.prefix} {self.nexthop} {self.distance}\nexit"
        success, output = self._exec(["vtysh", "-c", cmd])

        if success:
            self._injected = True
            return FaultResult(
                success=True,
                message=f"Injected static route {self.prefix} via {self.nexthop}",
                details={
                    "prefix": self.prefix,
                    "nexthop": self.nexthop,
                    "distance": self.distance,
                    "container": self.container
                }
            )
        else:
            return FaultResult(
                success=False,
                message=f"Failed to inject static route: {output}",
                details={"error": output}
            )

    def restore(self) -> FaultResult:
        """Remove the injected static route."""
        logger.info(f"Removing stale route: {self.prefix} on {self.container}")

        cmd = f"configure terminal\nno ip route {self.prefix} {self.nexthop} {self.distance}\nexit"
        success, output = self._exec(["vtysh", "-c", cmd])

        if success:
            self._injected = False
            return FaultResult(
                success=True,
                message=f"Removed static route {self.prefix}",
                details={"prefix": self.prefix, "container": self.container}
            )
        else:
            return FaultResult(
                success=False,
                message=f"Failed to remove static route: {output}",
                details={"error": output}
            )

    def verify(self) -> bool:
        """Verify static route is installed."""
        success, output = self._exec_vtysh(f"show ip route {self.prefix}")
        if not success:
            return False

        # Check if our static route with specific nexthop is present
        return self.nexthop in output and "static" in output.lower()

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        result = super().to_dict()
        result.update({
            "prefix": self.prefix,
            "nexthop": self.nexthop,
            "distance": self.distance,
        })
        return result


class MissingRoute(BaseFault):
    """
    Missing route fault.

    Removes an OSPF network statement, causing:
    - Route withdrawal from LSDB
    - Prefix unreachable from other routers
    """

    fault_class = FaultClass.MISSING_ROUTE
    description = "OSPF network withdrawn"

    def __init__(
        self,
        container: str,
        prefix: str,
        area: str = "0",
        container_prefix: str = CONTAINER_PREFIX
    ):
        """
        Initialize missing route fault.

        Args:
            container: Router container name
            prefix: Network prefix to withdraw (e.g., '192.168.1.0/24')
            area: OSPF area ID
            container_prefix: Container name prefix
        """
        super().__init__(container, container_prefix)
        self.prefix = prefix
        self.area = area

    def inject(self) -> FaultResult:
        """Remove OSPF network statement."""
        logger.info(
            f"Withdrawing OSPF network: {self.prefix} area {self.area} "
            f"on {self.container}"
        )

        cmd = f"configure terminal\nrouter ospf\nno network {self.prefix} area {self.area}\nexit\nexit"
        success, output = self._exec(["vtysh", "-c", cmd])

        if success:
            self._injected = True
            return FaultResult(
                success=True,
                message=f"Withdrew OSPF network {self.prefix}",
                details={
                    "prefix": self.prefix,
                    "area": self.area,
                    "container": self.container
                }
            )
        else:
            return FaultResult(
                success=False,
                message=f"Failed to withdraw network: {output}",
                details={"error": output}
            )

    def restore(self) -> FaultResult:
        """Restore OSPF network statement."""
        logger.info(f"Restoring OSPF network: {self.prefix} on {self.container}")

        cmd = f"configure terminal\nrouter ospf\nnetwork {self.prefix} area {self.area}\nexit\nexit"
        success, output = self._exec(["vtysh", "-c", cmd])

        if success:
            self._injected = False
            return FaultResult(
                success=True,
                message=f"Restored OSPF network {self.prefix}",
                details={"prefix": self.prefix, "container": self.container}
            )
        else:
            return FaultResult(
                success=False,
                message=f"Failed to restore network: {output}",
                details={"error": output}
            )

    def verify(self) -> bool:
        """Verify network is not being advertised."""
        success, output = self._exec_vtysh("show ip ospf interface")
        if not success:
            return False

        # Check if prefix is NOT in OSPF interfaces
        # This is a simplified check
        prefix_network = self.prefix.split("/")[0]
        return prefix_network not in output

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        result = super().to_dict()
        result.update({
            "prefix": self.prefix,
            "area": self.area,
        })
        return result


class CounterAnomaly(BaseFault):
    """
    Interface counter anomaly fault.

    Uses tc netem to introduce packet loss/errors, causing:
    - High error/drop counters
    - Potential OSPF adjacency issues at high loss rates
    """

    fault_class = FaultClass.COUNTER_ANOMALY
    description = "Interface packet loss/errors"

    def __init__(
        self,
        container: str,
        interface: str,
        loss_pct: float = 5.0,
        corrupt_pct: float = 0.0,
        container_prefix: str = CONTAINER_PREFIX
    ):
        """
        Initialize counter anomaly fault.

        Args:
            container: Router container name
            interface: Interface to affect
            loss_pct: Packet loss percentage (0-100)
            corrupt_pct: Packet corruption percentage (0-100)
            container_prefix: Container name prefix
        """
        super().__init__(container, container_prefix)
        self.interface = interface
        self.loss_pct = loss_pct
        self.corrupt_pct = corrupt_pct

    def inject(self) -> FaultResult:
        """Apply tc netem rules for packet loss."""
        logger.info(
            f"Injecting counter anomaly: {self.loss_pct}% loss on "
            f"{self.container}:{self.interface}"
        )

        # Build netem command
        netem_opts = []
        if self.loss_pct > 0:
            netem_opts.append(f"loss {self.loss_pct}%")
        if self.corrupt_pct > 0:
            netem_opts.append(f"corrupt {self.corrupt_pct}%")

        if not netem_opts:
            return FaultResult(
                success=False,
                message="No loss or corruption specified"
            )

        netem_str = " ".join(netem_opts)

        # First, remove any existing qdisc
        self._exec(["tc", "qdisc", "del", "dev", self.interface, "root"])

        # Add netem qdisc
        success, output = self._exec([
            "tc", "qdisc", "add", "dev", self.interface,
            "root", "netem", *netem_str.split()
        ])

        if success:
            self._injected = True
            return FaultResult(
                success=True,
                message=f"Applied {netem_str} on {self.container}:{self.interface}",
                details={
                    "interface": self.interface,
                    "container": self.container,
                    "loss_pct": self.loss_pct,
                    "corrupt_pct": self.corrupt_pct
                }
            )
        else:
            return FaultResult(
                success=False,
                message=f"Failed to apply netem: {output}",
                details={"error": output}
            )

    def restore(self) -> FaultResult:
        """Remove tc netem rules."""
        logger.info(
            f"Removing counter anomaly from {self.container}:{self.interface}"
        )

        success, output = self._exec([
            "tc", "qdisc", "del", "dev", self.interface, "root"
        ])

        if success or "No such file" in output or "RTNETLINK" in output:
            self._injected = False
            return FaultResult(
                success=True,
                message=f"Removed netem from {self.interface}",
                details={"interface": self.interface, "container": self.container}
            )
        else:
            return FaultResult(
                success=False,
                message=f"Failed to remove netem: {output}",
                details={"error": output}
            )

    def verify(self) -> bool:
        """Verify netem qdisc is active."""
        success, output = self._exec(["tc", "qdisc", "show", "dev", self.interface])
        if not success:
            return False

        return "netem" in output

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        result = super().to_dict()
        result.update({
            "interface": self.interface,
            "loss_pct": self.loss_pct,
            "corrupt_pct": self.corrupt_pct,
        })
        return result


# Factory function for creating faults from config
def create_fault(fault_config: dict[str, Any]) -> BaseFault:
    """
    Create a fault instance from configuration dictionary.

    Args:
        fault_config: Dict with fault_class and parameters

    Returns:
        Appropriate fault instance

    Raises:
        ValueError: If fault_class is unknown
    """
    fault_class = fault_config.get("fault_class")
    container = fault_config.get("container")
    prefix = fault_config.get("container_prefix", CONTAINER_PREFIX)

    if fault_class == FaultClass.LINK_FAILURE.value:
        return LinkFailure(
            container=container,
            interface=fault_config["interface"],
            container_prefix=prefix
        )
    elif fault_class == FaultClass.FLAPPING_LINK.value:
        return FlappingLink(
            container=container,
            interface=fault_config["interface"],
            period_sec=fault_config.get("period_sec", 5.0),
            count=fault_config.get("count", 3),
            container_prefix=prefix
        )
    elif fault_class == FaultClass.STALE_ROUTE.value:
        return StaleRoute(
            container=container,
            prefix=fault_config["prefix"],
            nexthop=fault_config["nexthop"],
            distance=fault_config.get("distance", 1),
            container_prefix=prefix
        )
    elif fault_class == FaultClass.MISSING_ROUTE.value:
        return MissingRoute(
            container=container,
            prefix=fault_config["prefix"],
            area=fault_config.get("area", "0"),
            container_prefix=prefix
        )
    elif fault_class == FaultClass.COUNTER_ANOMALY.value:
        return CounterAnomaly(
            container=container,
            interface=fault_config["interface"],
            loss_pct=fault_config.get("loss_pct", 5.0),
            corrupt_pct=fault_config.get("corrupt_pct", 0.0),
            container_prefix=prefix
        )
    else:
        raise ValueError(f"Unknown fault class: {fault_class}")
