"""
Pre-defined fault scenarios for SDN fault diagnosis experiments.

Provides:
- Single fault scenarios (one fault at a time)
- Compound fault scenarios (multiple simultaneous faults)
- Scenario selection and balancing utilities
"""

import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from .fault_types import FaultClass


class ScenarioType(str, Enum):
    """Classification of scenario complexity."""
    SINGLE = "single"
    COMPOUND = "compound"


@dataclass
class FaultSpec:
    """Specification for a single fault."""
    fault_class: FaultClass
    container: str
    params: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for injection."""
        return {
            "fault_class": self.fault_class.value,
            "container": self.container,
            **self.params
        }


@dataclass
class Scenario:
    """A complete fault scenario with one or more faults."""
    name: str
    description: str
    scenario_type: ScenarioType
    faults: list[FaultSpec]
    expected_symptoms: list[str] = field(default_factory=list)
    difficulty: int = 1  # 1-5 scale

    @property
    def fault_classes(self) -> list[FaultClass]:
        """Get list of fault classes in this scenario."""
        return [f.fault_class for f in self.faults]

    @property
    def is_compound(self) -> bool:
        """Check if this is a compound fault scenario."""
        return len(self.faults) > 1


# =============================================================================
# Single Fault Scenarios
# =============================================================================

# Link Failure Scenarios
SPINE1_LEAF1_LINK_DOWN = Scenario(
    name="spine1_leaf1_link_down",
    description="Spine1 to Leaf1 link failure",
    scenario_type=ScenarioType.SINGLE,
    faults=[
        FaultSpec(
            fault_class=FaultClass.LINK_FAILURE,
            container="spine1",
            params={"interface": "eth1"}
        )
    ],
    expected_symptoms=[
        "OSPF neighbor loss between spine1 and leaf1",
        "Router LSA update from spine1 with reduced link count",
        "Routing reconvergence via alternate spines"
    ],
    difficulty=1
)

SPINE2_LEAF2_LINK_DOWN = Scenario(
    name="spine2_leaf2_link_down",
    description="Spine2 to Leaf2 link failure",
    scenario_type=ScenarioType.SINGLE,
    faults=[
        FaultSpec(
            fault_class=FaultClass.LINK_FAILURE,
            container="spine2",
            params={"interface": "eth2"}
        )
    ],
    expected_symptoms=[
        "OSPF neighbor loss between spine2 and leaf2",
        "Router LSA update from spine2",
        "Traffic reroutes through other spines"
    ],
    difficulty=1
)

LEAF3_SPINE4_LINK_DOWN = Scenario(
    name="leaf3_spine4_link_down",
    description="Leaf3 to Spine4 link failure (from leaf side)",
    scenario_type=ScenarioType.SINGLE,
    faults=[
        FaultSpec(
            fault_class=FaultClass.LINK_FAILURE,
            container="leaf3",
            params={"interface": "eth4"}
        )
    ],
    expected_symptoms=[
        "OSPF neighbor loss between leaf3 and spine4",
        "Both leaf3 and spine4 update their Router LSAs"
    ],
    difficulty=1
)

# Flapping Link Scenarios
SPINE1_LEAF2_FLAPPING = Scenario(
    name="spine1_leaf2_flapping",
    description="Flapping link between spine1 and leaf2",
    scenario_type=ScenarioType.SINGLE,
    faults=[
        FaultSpec(
            fault_class=FaultClass.FLAPPING_LINK,
            container="spine1",
            params={"interface": "eth2", "period_sec": 5.0, "count": 3}
        )
    ],
    expected_symptoms=[
        "Multiple OSPF neighbor state transitions",
        "Repeated Router LSA updates",
        "Potential route flapping"
    ],
    difficulty=2
)

LEAF4_SPINE2_FLAPPING = Scenario(
    name="leaf4_spine2_flapping",
    description="Flapping link between leaf4 and spine2",
    scenario_type=ScenarioType.SINGLE,
    faults=[
        FaultSpec(
            fault_class=FaultClass.FLAPPING_LINK,
            container="leaf4",
            params={"interface": "eth2", "period_sec": 4.0, "count": 4}
        )
    ],
    expected_symptoms=[
        "Repeated neighbor down/up events",
        "LSA churn in LSDB",
        "Routing instability"
    ],
    difficulty=2
)

# Stale Route Scenarios
LEAF1_STALE_ROUTE_TO_LEAF3 = Scenario(
    name="leaf1_stale_route_to_leaf3",
    description="Stale route on leaf1 pointing to wrong nexthop for leaf3 subnet",
    scenario_type=ScenarioType.SINGLE,
    faults=[
        FaultSpec(
            fault_class=FaultClass.STALE_ROUTE,
            container="leaf1",
            params={
                "prefix": "192.168.3.0/24",
                "nexthop": "10.1.1.0",  # spine1 interface, not best path
                "distance": 1
            }
        )
    ],
    expected_symptoms=[
        "Static route overrides OSPF route",
        "Traffic from leaf1 to 192.168.3.0/24 takes suboptimal path",
        "Route table shows static route with lower distance"
    ],
    difficulty=2
)

LEAF2_STALE_ROUTE_TO_LEAF4 = Scenario(
    name="leaf2_stale_route_to_leaf4",
    description="Stale route on leaf2 for leaf4 host subnet",
    scenario_type=ScenarioType.SINGLE,
    faults=[
        FaultSpec(
            fault_class=FaultClass.STALE_ROUTE,
            container="leaf2",
            params={
                "prefix": "192.168.4.0/24",
                "nexthop": "10.1.2.0",  # spine2 interface
                "distance": 1
            }
        )
    ],
    expected_symptoms=[
        "Routing table inconsistency",
        "Potential traffic blackhole or loop"
    ],
    difficulty=2
)

# Missing Route Scenarios
LEAF1_MISSING_HOST_SUBNET = Scenario(
    name="leaf1_missing_host_subnet",
    description="Leaf1 withdraws its host subnet from OSPF",
    scenario_type=ScenarioType.SINGLE,
    faults=[
        FaultSpec(
            fault_class=FaultClass.MISSING_ROUTE,
            container="leaf1",
            params={"prefix": "192.168.1.0/24", "area": "0"}
        )
    ],
    expected_symptoms=[
        "192.168.1.0/24 disappears from LSDB",
        "Other routers lose route to leaf1 hosts",
        "Hosts behind leaf1 become unreachable from rest of network"
    ],
    difficulty=2
)

LEAF3_MISSING_HOST_SUBNET = Scenario(
    name="leaf3_missing_host_subnet",
    description="Leaf3 withdraws its host subnet from OSPF",
    scenario_type=ScenarioType.SINGLE,
    faults=[
        FaultSpec(
            fault_class=FaultClass.MISSING_ROUTE,
            container="leaf3",
            params={"prefix": "192.168.3.0/24", "area": "0"}
        )
    ],
    expected_symptoms=[
        "192.168.3.0/24 removed from routing tables network-wide",
        "Host5 and host6 unreachable"
    ],
    difficulty=2
)

# Counter Anomaly Scenarios
SPINE1_ETH1_PACKET_LOSS = Scenario(
    name="spine1_eth1_packet_loss",
    description="5% packet loss on spine1 eth1",
    scenario_type=ScenarioType.SINGLE,
    faults=[
        FaultSpec(
            fault_class=FaultClass.COUNTER_ANOMALY,
            container="spine1",
            params={"interface": "eth1", "loss_pct": 5.0}
        )
    ],
    expected_symptoms=[
        "Elevated error/drop counters on spine1 eth1",
        "Possible OSPF hello loss but adjacency should remain",
        "Performance degradation"
    ],
    difficulty=1
)

LEAF2_ETH3_HIGH_LOSS = Scenario(
    name="leaf2_eth3_high_loss",
    description="10% packet loss on leaf2 eth3 (to spine3)",
    scenario_type=ScenarioType.SINGLE,
    faults=[
        FaultSpec(
            fault_class=FaultClass.COUNTER_ANOMALY,
            container="leaf2",
            params={"interface": "eth3", "loss_pct": 10.0}
        )
    ],
    expected_symptoms=[
        "High loss counter on leaf2 eth3",
        "Potential OSPF adjacency instability at 10% loss"
    ],
    difficulty=2
)

# =============================================================================
# Compound Fault Scenarios
# =============================================================================

DUAL_LINK_FAILURE = Scenario(
    name="dual_link_failure",
    description="Two simultaneous link failures isolating leaf1",
    scenario_type=ScenarioType.COMPOUND,
    faults=[
        FaultSpec(
            fault_class=FaultClass.LINK_FAILURE,
            container="spine1",
            params={"interface": "eth1"}
        ),
        FaultSpec(
            fault_class=FaultClass.LINK_FAILURE,
            container="spine2",
            params={"interface": "eth1"}
        )
    ],
    expected_symptoms=[
        "Two OSPF neighbor losses on leaf1",
        "Leaf1 loses connectivity to spine1 and spine2",
        "Traffic must route through spine3 and spine4"
    ],
    difficulty=3
)

LINK_FAILURE_PLUS_STALE_ROUTE = Scenario(
    name="link_failure_plus_stale_route",
    description="Link failure combined with stale route on alternate path",
    scenario_type=ScenarioType.COMPOUND,
    faults=[
        FaultSpec(
            fault_class=FaultClass.LINK_FAILURE,
            container="spine1",
            params={"interface": "eth2"}
        ),
        FaultSpec(
            fault_class=FaultClass.STALE_ROUTE,
            container="leaf2",
            params={
                "prefix": "10.0.0.1/32",  # spine1 loopback
                "nexthop": "10.1.2.2",  # spine2 via leaf2
                "distance": 1
            }
        )
    ],
    expected_symptoms=[
        "Link failure causes neighbor loss",
        "Stale route may cause routing loop or blackhole",
        "Complex interaction between failures"
    ],
    difficulty=4
)

FLAPPING_PLUS_COUNTER_ANOMALY = Scenario(
    name="flapping_plus_counter_anomaly",
    description="Flapping link with packet loss on adjacent link",
    scenario_type=ScenarioType.COMPOUND,
    faults=[
        FaultSpec(
            fault_class=FaultClass.FLAPPING_LINK,
            container="spine3",
            params={"interface": "eth1", "period_sec": 6.0, "count": 2}
        ),
        FaultSpec(
            fault_class=FaultClass.COUNTER_ANOMALY,
            container="spine3",
            params={"interface": "eth2", "loss_pct": 8.0}
        )
    ],
    expected_symptoms=[
        "Flapping on one interface",
        "High loss on another interface",
        "Compound network instability"
    ],
    difficulty=3
)

MISSING_ROUTE_PLUS_LINK_FAILURE = Scenario(
    name="missing_route_plus_link_failure",
    description="Route withdrawal combined with link failure",
    scenario_type=ScenarioType.COMPOUND,
    faults=[
        FaultSpec(
            fault_class=FaultClass.MISSING_ROUTE,
            container="leaf4",
            params={"prefix": "192.168.4.0/24", "area": "0"}
        ),
        FaultSpec(
            fault_class=FaultClass.LINK_FAILURE,
            container="leaf4",
            params={"interface": "eth1"}
        )
    ],
    expected_symptoms=[
        "Host subnet withdrawn",
        "Link failure reduces connectivity",
        "Leaf4 partially isolated with missing routes"
    ],
    difficulty=4
)

TRIPLE_FAULT = Scenario(
    name="triple_fault",
    description="Three simultaneous faults across the network",
    scenario_type=ScenarioType.COMPOUND,
    faults=[
        FaultSpec(
            fault_class=FaultClass.LINK_FAILURE,
            container="spine1",
            params={"interface": "eth3"}
        ),
        FaultSpec(
            fault_class=FaultClass.STALE_ROUTE,
            container="leaf1",
            params={
                "prefix": "192.168.4.0/24",
                "nexthop": "10.1.1.0",
                "distance": 1
            }
        ),
        FaultSpec(
            fault_class=FaultClass.COUNTER_ANOMALY,
            container="spine4",
            params={"interface": "eth4", "loss_pct": 7.0}
        )
    ],
    expected_symptoms=[
        "Multiple simultaneous issues",
        "Complex diagnosis required",
        "Interactions between faults"
    ],
    difficulty=5
)


# =============================================================================
# Scenario Collections
# =============================================================================

SINGLE_FAULT_SCENARIOS = [
    # Link failures
    SPINE1_LEAF1_LINK_DOWN,
    SPINE2_LEAF2_LINK_DOWN,
    LEAF3_SPINE4_LINK_DOWN,
    # Flapping
    SPINE1_LEAF2_FLAPPING,
    LEAF4_SPINE2_FLAPPING,
    # Stale routes
    LEAF1_STALE_ROUTE_TO_LEAF3,
    LEAF2_STALE_ROUTE_TO_LEAF4,
    # Missing routes
    LEAF1_MISSING_HOST_SUBNET,
    LEAF3_MISSING_HOST_SUBNET,
    # Counter anomalies
    SPINE1_ETH1_PACKET_LOSS,
    LEAF2_ETH3_HIGH_LOSS,
]

COMPOUND_FAULT_SCENARIOS = [
    DUAL_LINK_FAILURE,
    LINK_FAILURE_PLUS_STALE_ROUTE,
    FLAPPING_PLUS_COUNTER_ANOMALY,
    MISSING_ROUTE_PLUS_LINK_FAILURE,
    TRIPLE_FAULT,
]

ALL_SCENARIOS = SINGLE_FAULT_SCENARIOS + COMPOUND_FAULT_SCENARIOS


def get_scenarios_by_type(scenario_type: ScenarioType) -> list[Scenario]:
    """Get all scenarios of a specific type."""
    if scenario_type == ScenarioType.SINGLE:
        return SINGLE_FAULT_SCENARIOS
    return COMPOUND_FAULT_SCENARIOS


def get_scenarios_by_fault_class(fault_class: FaultClass) -> list[Scenario]:
    """Get all scenarios that include a specific fault class."""
    return [s for s in ALL_SCENARIOS if fault_class in s.fault_classes]


def get_balanced_scenario_set(
    total: int,
    compound_ratio: float = 0.2
) -> list[Scenario]:
    """
    Get a balanced set of scenarios for evaluation.

    Args:
        total: Total number of scenarios to return
        compound_ratio: Ratio of compound to single fault scenarios

    Returns:
        List of selected scenarios (may have repeats)
    """
    compound_count = int(total * compound_ratio)
    single_count = total - compound_count

    scenarios = []

    # Select compound scenarios
    for _ in range(compound_count):
        scenarios.append(random.choice(COMPOUND_FAULT_SCENARIOS))

    # Balance single fault scenarios across fault classes
    fault_classes = list(FaultClass)
    per_class = single_count // len(fault_classes)
    remainder = single_count % len(fault_classes)

    for fc in fault_classes:
        fc_scenarios = get_scenarios_by_fault_class(fc)
        fc_single = [s for s in fc_scenarios if s.scenario_type == ScenarioType.SINGLE]
        if fc_single:
            count = per_class + (1 if remainder > 0 else 0)
            remainder = max(0, remainder - 1)
            for _ in range(count):
                scenarios.append(random.choice(fc_single))

    random.shuffle(scenarios)
    return scenarios


def generate_random_scenario(
    scenario_type: Optional[ScenarioType] = None
) -> Scenario:
    """
    Generate a random scenario.

    Args:
        scenario_type: Specific type, or None for random

    Returns:
        Random scenario
    """
    if scenario_type is None:
        return random.choice(ALL_SCENARIOS)
    elif scenario_type == ScenarioType.SINGLE:
        return random.choice(SINGLE_FAULT_SCENARIOS)
    else:
        return random.choice(COMPOUND_FAULT_SCENARIOS)
