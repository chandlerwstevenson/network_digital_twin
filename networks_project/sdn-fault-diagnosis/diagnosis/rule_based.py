"""
Rule-based diagnostic engine for OSPF network fault detection.

Implements systematic analysis of network telemetry:
1. LSDB diff - Compare Router-LSAs for topology changes
2. Neighbor check - Flag non-Full adjacencies
3. Route audit - Verify next-hop reachability
4. Counter analysis - Detect error/drop rate anomalies
5. Diagnosis assembly - Aggregate findings into structured output
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

import sys
sys.path.insert(0, str(__file__).rsplit('/', 2)[0])

from telemetry.schemas import (
    DiagnosisResult,
    NetworkSnapshot,
    RouterTelemetry,
)
from telemetry.snapshot import SnapshotDiff

from .base import (
    BaseDiagnosticEngine,
    DiagnosisConfig,
    create_diagnosis,
    no_fault_result,
)

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """A single diagnostic finding."""
    category: str  # lsdb, neighbor, route, counter
    severity: str  # critical, warning, info
    router: str
    component: str  # interface, neighbor_id, prefix
    description: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisState:
    """State accumulated during analysis."""
    findings: list[Finding] = field(default_factory=list)
    affected_routers: set[str] = field(default_factory=set)
    affected_interfaces: set[str] = field(default_factory=set)
    affected_prefixes: set[str] = field(default_factory=set)

    def add_finding(self, finding: Finding):
        """Add a finding and update affected components."""
        self.findings.append(finding)
        self.affected_routers.add(finding.router)
        if finding.category in ("neighbor", "counter", "lsdb"):
            self.affected_interfaces.add(f"{finding.router}:{finding.component}")
        elif finding.category == "route":
            self.affected_prefixes.add(finding.component)

    @property
    def has_critical(self) -> bool:
        """Check if there are any critical findings."""
        return any(f.severity == "critical" for f in self.findings)

    @property
    def critical_findings(self) -> list[Finding]:
        """Get critical findings only."""
        return [f for f in self.findings if f.severity == "critical"]

    @property
    def warning_findings(self) -> list[Finding]:
        """Get warning findings only."""
        return [f for f in self.findings if f.severity == "warning"]


class RuleBasedEngine(BaseDiagnosticEngine):
    """
    Rule-based diagnostic engine using decision tree logic.

    Analyzes network telemetry through a series of checks:
    1. LSDB analysis for topology changes
    2. Neighbor state verification
    3. Routing table audit
    4. Interface counter analysis
    """

    def __init__(self, config: DiagnosisConfig = None):
        """
        Initialize the rule-based engine.

        Args:
            config: Diagnosis configuration parameters
        """
        super().__init__(name="rule-based")
        self.config = config or DiagnosisConfig()

    def diagnose(
        self,
        snapshot: NetworkSnapshot,
        previous_snapshot: Optional[NetworkSnapshot] = None
    ) -> DiagnosisResult:
        """
        Analyze network snapshot and produce diagnosis.

        Args:
            snapshot: Current network state
            previous_snapshot: Previous snapshot for diff analysis

        Returns:
            DiagnosisResult with fault classification
        """
        state = AnalysisState()

        # Run all analysis phases
        self._analyze_neighbors(snapshot, state)
        self._analyze_counters(snapshot, state)

        if previous_snapshot:
            self._analyze_lsdb_diff(snapshot, previous_snapshot, state)
            self._analyze_route_changes(snapshot, previous_snapshot, state)
        else:
            self._analyze_lsdb_static(snapshot, state)
            self._analyze_routes_static(snapshot, state)

        # Assemble diagnosis from findings
        return self._assemble_diagnosis(state)

    def _analyze_neighbors(
        self,
        snapshot: NetworkSnapshot,
        state: AnalysisState
    ):
        """
        Analyze OSPF neighbor states.

        Flags:
        - Non-Full adjacencies (critical)
        - Missing expected neighbors (critical)
        """
        for router_name, telemetry in snapshot.routers.items():
            non_full = telemetry.non_full_adjacencies

            for neighbor in non_full:
                state.add_finding(Finding(
                    category="neighbor",
                    severity="critical",
                    router=router_name,
                    component=neighbor.interface,
                    description=f"Neighbor {neighbor.neighbor_id} in state {neighbor.state}",
                    details={
                        "neighbor_id": neighbor.neighbor_id,
                        "state": neighbor.state,
                        "interface": neighbor.interface,
                    }
                ))

            # Check if router has no neighbors at all (potential isolation)
            if not telemetry.neighbors:
                # This could be normal for hosts, but critical for spine/leaf
                if router_name.startswith(("spine", "leaf")):
                    state.add_finding(Finding(
                        category="neighbor",
                        severity="critical",
                        router=router_name,
                        component="all",
                        description="Router has no OSPF neighbors",
                        details={"neighbor_count": 0}
                    ))

    def _analyze_counters(
        self,
        snapshot: NetworkSnapshot,
        state: AnalysisState
    ):
        """
        Analyze interface counters for anomalies.

        Flags:
        - High error rate (warning if >1%, critical if >5%)
        - High drop rate (warning if >1%, critical if >5%)
        """
        for router_name, telemetry in snapshot.routers.items():
            for iface_name, interface in telemetry.interfaces.items():
                counters = interface.counters

                # Check error rate
                if counters.error_rate > 5.0:
                    state.add_finding(Finding(
                        category="counter",
                        severity="critical",
                        router=router_name,
                        component=iface_name,
                        description=f"Critical error rate: {counters.error_rate:.1f}%",
                        details={
                            "error_rate": counters.error_rate,
                            "rx_errors": counters.rx_errors,
                            "tx_errors": counters.tx_errors,
                        }
                    ))
                elif counters.error_rate > self.config.error_rate_threshold:
                    state.add_finding(Finding(
                        category="counter",
                        severity="warning",
                        router=router_name,
                        component=iface_name,
                        description=f"Elevated error rate: {counters.error_rate:.1f}%",
                        details={"error_rate": counters.error_rate}
                    ))

                # Check drop rate
                if counters.drop_rate > 5.0:
                    state.add_finding(Finding(
                        category="counter",
                        severity="critical",
                        router=router_name,
                        component=iface_name,
                        description=f"Critical drop rate: {counters.drop_rate:.1f}%",
                        details={
                            "drop_rate": counters.drop_rate,
                            "rx_dropped": counters.rx_dropped,
                            "tx_dropped": counters.tx_dropped,
                        }
                    ))
                elif counters.drop_rate > self.config.drop_rate_threshold:
                    state.add_finding(Finding(
                        category="counter",
                        severity="warning",
                        router=router_name,
                        component=iface_name,
                        description=f"Elevated drop rate: {counters.drop_rate:.1f}%",
                        details={"drop_rate": counters.drop_rate}
                    ))

                # Check interface status
                if interface.link_status.lower() == "down":
                    state.add_finding(Finding(
                        category="counter",
                        severity="critical",
                        router=router_name,
                        component=iface_name,
                        description="Interface link is down",
                        details={
                            "admin_status": interface.status,
                            "link_status": interface.link_status,
                        }
                    ))

    def _analyze_lsdb_diff(
        self,
        current: NetworkSnapshot,
        previous: NetworkSnapshot,
        state: AnalysisState
    ):
        """
        Analyze LSDB changes between snapshots.

        Flags:
        - LSA withdrawals (critical)
        - Link count reductions (warning/critical)
        - New LSAs (info)
        """
        diff = SnapshotDiff(previous, current)
        diff_data = diff.compute()

        for router_name, router_diff in diff_data.get("router_diffs", {}).items():
            lsdb_changes = router_diff.get("lsdb_changes", {})

            # Removed LSAs indicate topology change
            for lsa_id in lsdb_changes.get("router_lsas_removed", []):
                state.add_finding(Finding(
                    category="lsdb",
                    severity="critical",
                    router=router_name,
                    component=lsa_id,
                    description=f"Router LSA {lsa_id} withdrawn from LSDB",
                    details={"lsa_id": lsa_id, "action": "removed"}
                ))

            # Modified LSAs - check link count changes
            for mod in lsdb_changes.get("router_lsas_modified", []):
                if mod["new_link_count"] < mod["old_link_count"]:
                    state.add_finding(Finding(
                        category="lsdb",
                        severity="warning",
                        router=router_name,
                        component=mod["lsa_id"],
                        description=f"LSA link count reduced: {mod['old_link_count']} -> {mod['new_link_count']}",
                        details=mod
                    ))

    def _analyze_route_changes(
        self,
        current: NetworkSnapshot,
        previous: NetworkSnapshot,
        state: AnalysisState
    ):
        """
        Analyze routing table changes between snapshots.

        Flags:
        - Route withdrawals (critical for host subnets)
        - Next-hop changes (warning)
        - New static routes overriding OSPF (warning)
        """
        diff = SnapshotDiff(previous, current)
        diff_data = diff.compute()

        for router_name, router_diff in diff_data.get("router_diffs", {}).items():
            route_changes = router_diff.get("route_changes", {})

            # Removed routes
            for prefix in route_changes.get("routes_removed", []):
                # Host subnets are more critical
                severity = "critical" if prefix.startswith("192.168.") else "warning"
                state.add_finding(Finding(
                    category="route",
                    severity=severity,
                    router=router_name,
                    component=prefix,
                    description=f"Route to {prefix} withdrawn",
                    details={"prefix": prefix, "action": "removed"}
                ))

            # Modified routes (next-hop changes)
            for mod in route_changes.get("routes_modified", []):
                if mod["nexthops_removed"]:
                    state.add_finding(Finding(
                        category="route",
                        severity="warning",
                        router=router_name,
                        component=mod["prefix"],
                        description=f"Route {mod['prefix']} next-hop changed",
                        details=mod
                    ))

    def _analyze_lsdb_static(
        self,
        snapshot: NetworkSnapshot,
        state: AnalysisState
    ):
        """
        Static LSDB analysis when no previous snapshot available.

        Checks for:
        - Inconsistent LSA counts across routers
        - Missing expected LSAs
        """
        # Get all unique router LSA IDs across network
        all_lsa_ids: set[str] = set()
        router_lsa_counts: dict[str, int] = {}

        for router_name, telemetry in snapshot.routers.items():
            lsa_ids = {lsa.lsa_id for lsa in telemetry.lsdb.router_lsas}
            all_lsa_ids.update(lsa_ids)
            router_lsa_counts[router_name] = len(lsa_ids)

        # Check if any router is missing LSAs that others have
        expected_count = len(all_lsa_ids)
        for router_name, count in router_lsa_counts.items():
            if count < expected_count:
                state.add_finding(Finding(
                    category="lsdb",
                    severity="warning",
                    router=router_name,
                    component="lsdb",
                    description=f"LSDB incomplete: {count}/{expected_count} Router LSAs",
                    details={
                        "router_lsa_count": count,
                        "expected_count": expected_count,
                    }
                ))

    def _analyze_routes_static(
        self,
        snapshot: NetworkSnapshot,
        state: AnalysisState
    ):
        """
        Static route analysis when no previous snapshot available.

        Checks for:
        - Routes with unreachable next-hops
        - Static routes that might override OSPF
        - Missing expected prefixes
        """
        # Expected host subnets
        expected_host_subnets = {
            "192.168.1.0/24": "leaf1",
            "192.168.2.0/24": "leaf2",
            "192.168.3.0/24": "leaf3",
            "192.168.4.0/24": "leaf4",
        }

        for router_name, telemetry in snapshot.routers.items():
            # Check if spines have routes to all host subnets
            if router_name.startswith("spine"):
                for prefix, owner in expected_host_subnets.items():
                    if prefix not in telemetry.routing_table.routes:
                        state.add_finding(Finding(
                            category="route",
                            severity="warning",
                            router=router_name,
                            component=prefix,
                            description=f"Missing route to {prefix} (owned by {owner})",
                            details={"prefix": prefix, "expected_owner": owner}
                        ))

            # Check for static routes (potential stale routes)
            for prefix, routes in telemetry.routing_table.routes.items():
                for route in routes:
                    if route.protocol == "static":
                        # Static routes in an OSPF network are suspicious
                        state.add_finding(Finding(
                            category="route",
                            severity="warning",
                            router=router_name,
                            component=prefix,
                            description=f"Static route found: {prefix}",
                            details={
                                "prefix": prefix,
                                "protocol": "static",
                                "distance": route.distance,
                                "nexthops": [nh.ip for nh in route.nexthops],
                            }
                        ))

    def _assemble_diagnosis(self, state: AnalysisState) -> DiagnosisResult:
        """
        Assemble findings into final diagnosis.

        Uses decision tree to classify fault type:
        1. Link failure: Interface down + neighbor loss
        2. Flapping: Multiple neighbor state changes (needs history)
        3. Stale route: Static route present
        4. Missing route: Route withdrawn + LSDB changes
        5. Counter anomaly: High error/drop rates
        """
        if not state.findings:
            return no_fault_result("All checks passed - network is healthy")

        # Categorize findings
        neighbor_findings = [f for f in state.findings if f.category == "neighbor"]
        counter_findings = [f for f in state.findings if f.category == "counter"]
        lsdb_findings = [f for f in state.findings if f.category == "lsdb"]
        route_findings = [f for f in state.findings if f.category == "route"]

        # Decision tree for fault classification
        fault_class = None
        location = None
        confidence = 0.0
        reasoning_parts = []

        # Check for link failure (interface down + neighbor loss)
        interface_down = [
            f for f in counter_findings
            if "link is down" in f.description
        ]
        if interface_down and neighbor_findings:
            fault_class = "link_failure"
            location = f"{interface_down[0].router}:{interface_down[0].component}"
            confidence = 0.95
            reasoning_parts.append(
                f"Interface {location} is down, causing neighbor loss"
            )

        # Check for neighbor loss without interface down (could be remote failure)
        elif neighbor_findings and not interface_down:
            critical_neighbor = [f for f in neighbor_findings if f.severity == "critical"]
            if critical_neighbor:
                # Might be link failure on remote end or flapping
                fault_class = "link_failure"
                f = critical_neighbor[0]
                location = f"{f.router}:{f.component}"
                confidence = 0.75
                reasoning_parts.append(
                    f"Neighbor {f.details.get('neighbor_id')} lost on {f.router}:{f.component}"
                )

        # Check for stale route (static route present)
        elif route_findings:
            static_routes = [f for f in route_findings if "Static route" in f.description]
            withdrawn_routes = [f for f in route_findings if "withdrawn" in f.description]

            if static_routes:
                fault_class = "stale_route"
                f = static_routes[0]
                location = f"{f.router}:{f.component}"
                confidence = 0.85
                reasoning_parts.append(
                    f"Static route on {f.router} for {f.component} may override OSPF"
                )
            elif withdrawn_routes:
                fault_class = "missing_route"
                f = withdrawn_routes[0]
                location = f"{f.router}:{f.component}"
                confidence = 0.85
                reasoning_parts.append(
                    f"Route to {f.component} withdrawn on {f.router}"
                )

        # Check for counter anomalies
        elif counter_findings:
            high_error = [f for f in counter_findings if "error rate" in f.description]
            high_drop = [f for f in counter_findings if "drop rate" in f.description]

            if high_error or high_drop:
                fault_class = "counter_anomaly"
                f = (high_error or high_drop)[0]
                location = f"{f.router}:{f.component}"
                confidence = 0.80
                reasoning_parts.append(f.description)

        # Check for LSDB inconsistencies
        elif lsdb_findings:
            fault_class = "missing_route"  # LSDB changes often mean route issues
            f = lsdb_findings[0]
            location = f"{f.router}:{f.component}"
            confidence = 0.70
            reasoning_parts.append(f.description)

        # Build remediation suggestion
        remediation = self._suggest_remediation(fault_class, location, state)

        if fault_class:
            return create_diagnosis(
                fault_class=fault_class,
                location=location,
                confidence=confidence,
                reasoning="; ".join(reasoning_parts),
                affected_routers=list(state.affected_routers),
                affected_interfaces=list(state.affected_interfaces),
                affected_prefixes=list(state.affected_prefixes),
                remediation=remediation
            )
        else:
            # Some findings but no clear classification
            return DiagnosisResult(
                fault_detected=True,
                fault_class="unknown",
                location=list(state.affected_routers)[0] if state.affected_routers else None,
                confidence=0.5,
                reasoning="Anomalies detected but fault type unclear",
                affected_routers=list(state.affected_routers),
            )

    def _suggest_remediation(
        self,
        fault_class: Optional[str],
        location: Optional[str],
        state: AnalysisState
    ) -> Optional[str]:
        """Generate remediation suggestion based on fault class."""
        if not fault_class or not location:
            return None

        suggestions = {
            "link_failure": f"Bring interface {location} back up: "
                           f"'ip link set <interface> up' or check physical connectivity",
            "flapping_link": f"Investigate instability on {location}: "
                            f"check cables, transceivers, and peer configuration",
            "stale_route": f"Remove incorrect static route on {location.split(':')[0]}: "
                          f"'no ip route <prefix>'",
            "missing_route": f"Restore OSPF network statement: "
                            f"'network <prefix> area 0' on affected router",
            "counter_anomaly": f"Investigate packet loss on {location}: "
                              f"check for congestion, errors, or QoS issues",
        }

        return suggestions.get(fault_class)
