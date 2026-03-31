"""
Pydantic models for OSPF telemetry data structures.

These schemas define the structure of data collected from FRRouting vtysh commands:
- show ip ospf database json
- show ip route json
- show ip ospf neighbor json
- show interface json
"""

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class OSPFNeighborState(str, Enum):
    """OSPF neighbor states as defined in RFC 2328."""
    DOWN = "Down"
    ATTEMPT = "Attempt"
    INIT = "Init"
    TWO_WAY = "2-Way"
    EXSTART = "ExStart"
    EXCHANGE = "Exchange"
    LOADING = "Loading"
    FULL = "Full"


class OSPFNeighbor(BaseModel):
    """Represents an OSPF neighbor."""
    neighbor_id: str = Field(..., description="Router ID of the neighbor")
    priority: int = Field(default=1, description="OSPF priority")
    state: str = Field(..., description="Current neighbor state")
    dead_time_msec: int = Field(default=0, description="Dead timer in milliseconds")
    address: str = Field(..., description="IP address of the neighbor")
    interface: str = Field(..., description="Local interface to neighbor")
    retransmit_counter: int = Field(default=0, description="Retransmit queue length")
    request_counter: int = Field(default=0, description="Request queue length")
    db_summary_counter: int = Field(default=0, description="DB summary queue length")

    @property
    def is_full(self) -> bool:
        """Check if neighbor is in Full state (handles 'Full/-' for point-to-point)."""
        return self.state.lower().startswith("full")


class RouterLSA(BaseModel):
    """Router LSA (Type 1) information."""
    lsa_id: str = Field(..., description="LSA ID (usually router ID)")
    advertising_router: str = Field(..., description="Router that originated this LSA")
    lsa_age: int = Field(default=0, description="LSA age in seconds")
    sequence_number: str = Field(default="0x80000001", description="LSA sequence number")
    checksum: str = Field(default="0x0000", description="LSA checksum")
    link_count: int = Field(default=0, description="Number of links in this LSA")
    links: list[dict[str, Any]] = Field(default_factory=list, description="Link descriptions")


class NetworkLSA(BaseModel):
    """Network LSA (Type 2) information."""
    lsa_id: str = Field(..., description="LSA ID (DR's interface IP)")
    advertising_router: str = Field(..., description="Designated Router ID")
    lsa_age: int = Field(default=0, description="LSA age in seconds")
    sequence_number: str = Field(default="0x80000001", description="LSA sequence number")
    network_mask: str = Field(default="255.255.255.0", description="Network mask")
    attached_routers: list[str] = Field(default_factory=list, description="Attached router IDs")


class OSPFLSDB(BaseModel):
    """OSPF Link State Database."""
    router_lsas: list[RouterLSA] = Field(default_factory=list, description="Type 1 Router LSAs")
    network_lsas: list[NetworkLSA] = Field(default_factory=list, description="Type 2 Network LSAs")
    area_id: str = Field(default="0.0.0.0", description="OSPF area ID")


class RouteNexthop(BaseModel):
    """Next-hop information for a route."""
    ip: str = Field(..., description="Next-hop IP address")
    interface: str = Field(..., description="Outgoing interface")
    active: bool = Field(default=True, description="Whether this nexthop is active")
    directly_connected: bool = Field(default=False, description="Directly connected route")


class Route(BaseModel):
    """IP route entry."""
    prefix: str = Field(..., description="Destination prefix")
    prefix_len: int = Field(..., description="Prefix length")
    protocol: str = Field(..., description="Protocol that installed this route")
    distance: int = Field(default=110, description="Administrative distance")
    metric: int = Field(default=0, description="Route metric")
    nexthops: list[RouteNexthop] = Field(default_factory=list, description="Next-hops")
    uptime: str = Field(default="00:00:00", description="Route uptime")
    selected: bool = Field(default=True, description="Whether this route is selected")
    installed: bool = Field(default=True, description="Whether this route is installed in FIB")


class RoutingTable(BaseModel):
    """IP routing table."""
    routes: dict[str, list[Route]] = Field(
        default_factory=dict,
        description="Routes keyed by destination prefix"
    )


class InterfaceCounters(BaseModel):
    """Interface packet counters."""
    rx_packets: int = Field(default=0, description="Received packets")
    rx_bytes: int = Field(default=0, description="Received bytes")
    rx_errors: int = Field(default=0, description="Receive errors")
    rx_dropped: int = Field(default=0, description="Dropped received packets")
    tx_packets: int = Field(default=0, description="Transmitted packets")
    tx_bytes: int = Field(default=0, description="Transmitted bytes")
    tx_errors: int = Field(default=0, description="Transmit errors")
    tx_dropped: int = Field(default=0, description="Dropped transmitted packets")

    @property
    def error_rate(self) -> float:
        """Calculate error rate as percentage of total packets."""
        total = self.rx_packets + self.tx_packets
        if total == 0:
            return 0.0
        errors = self.rx_errors + self.tx_errors
        return (errors / total) * 100

    @property
    def drop_rate(self) -> float:
        """Calculate drop rate as percentage of total packets."""
        total = self.rx_packets + self.tx_packets
        if total == 0:
            return 0.0
        drops = self.rx_dropped + self.tx_dropped
        return (drops / total) * 100


class Interface(BaseModel):
    """Network interface information."""
    name: str = Field(..., description="Interface name")
    status: str = Field(default="up", description="Administrative status")
    link_status: str = Field(default="up", description="Link/operational status")
    mtu: int = Field(default=1500, description="Maximum transmission unit")
    ip_addresses: list[str] = Field(default_factory=list, description="IP addresses configured")
    counters: InterfaceCounters = Field(
        default_factory=InterfaceCounters,
        description="Packet counters"
    )
    speed: Optional[int] = Field(default=None, description="Link speed in Mbps")


class RouterTelemetry(BaseModel):
    """Complete telemetry snapshot for a single router."""
    router_name: str = Field(..., description="Router hostname")
    router_id: str = Field(default="0.0.0.0", description="OSPF router ID")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Collection timestamp")
    lsdb: OSPFLSDB = Field(default_factory=OSPFLSDB, description="OSPF LSDB")
    neighbors: list[OSPFNeighbor] = Field(default_factory=list, description="OSPF neighbors")
    routing_table: RoutingTable = Field(default_factory=RoutingTable, description="IP routing table")
    interfaces: dict[str, Interface] = Field(
        default_factory=dict,
        description="Interface information keyed by name"
    )

    @property
    def full_adjacencies(self) -> list[OSPFNeighbor]:
        """Return only neighbors in Full state."""
        return [n for n in self.neighbors if n.is_full]

    @property
    def non_full_adjacencies(self) -> list[OSPFNeighbor]:
        """Return neighbors not in Full state."""
        return [n for n in self.neighbors if not n.is_full]


class NetworkSnapshot(BaseModel):
    """Complete network state snapshot."""
    snapshot_id: str = Field(..., description="Unique snapshot identifier")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Collection timestamp")
    routers: dict[str, RouterTelemetry] = Field(
        default_factory=dict,
        description="Router telemetry keyed by router name"
    )
    collection_duration_ms: int = Field(default=0, description="Time to collect snapshot in ms")

    @property
    def router_names(self) -> list[str]:
        """List of all router names in this snapshot."""
        return list(self.routers.keys())

    @property
    def total_neighbors(self) -> int:
        """Total number of OSPF neighbor relationships."""
        return sum(len(r.neighbors) for r in self.routers.values())

    @property
    def total_full_adjacencies(self) -> int:
        """Total number of Full adjacencies."""
        return sum(len(r.full_adjacencies) for r in self.routers.values())


class DiagnosisResult(BaseModel):
    """Result from a diagnostic engine."""
    fault_detected: bool = Field(..., description="Whether a fault was detected")
    fault_class: Optional[str] = Field(default=None, description="Classification of the fault")
    location: Optional[str] = Field(default=None, description="Affected component/location")
    affected_routers: list[str] = Field(default_factory=list, description="List of affected routers")
    affected_interfaces: list[str] = Field(default_factory=list, description="List of affected interfaces")
    affected_prefixes: list[str] = Field(default_factory=list, description="List of affected prefixes")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence score")
    reasoning: str = Field(default="", description="Explanation of diagnosis")
    remediation: Optional[str] = Field(default=None, description="Suggested remediation steps")
    diagnosis_time_ms: int = Field(default=0, description="Time to produce diagnosis in ms")
    raw_output: Optional[str] = Field(default=None, description="Raw output from diagnostic engine")

    class Config:
        json_schema_extra = {
            "example": {
                "fault_detected": True,
                "fault_class": "link_failure",
                "location": "spine1:eth1",
                "affected_routers": ["spine1", "leaf1"],
                "affected_interfaces": ["spine1:eth1", "leaf1:eth1"],
                "affected_prefixes": [],
                "confidence": 0.95,
                "reasoning": "Interface eth1 on spine1 is down, causing OSPF neighbor loss",
                "remediation": "Bring interface spine1:eth1 back up",
                "diagnosis_time_ms": 150
            }
        }


class TrialResult(BaseModel):
    """Result of a single experimental trial."""
    trial_id: str = Field(..., description="Unique trial identifier")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Ground truth
    injected_fault_type: str = Field(..., description="Type of fault injected")
    injected_fault_location: str = Field(..., description="Where fault was injected")
    injected_fault_params: dict[str, Any] = Field(
        default_factory=dict,
        description="Fault parameters"
    )

    # Snapshots
    pre_fault_snapshot_id: str = Field(..., description="Snapshot before fault injection")
    post_fault_snapshot_id: str = Field(..., description="Snapshot after fault injection")

    # Diagnoses
    rule_based_diagnosis: DiagnosisResult = Field(..., description="Rule-based engine result")
    llm_diagnosis: DiagnosisResult = Field(..., description="LLM agent result")
    ml_diagnosis: Optional[DiagnosisResult] = Field(default=None, description="ML engine result")
    hybrid_diagnosis: Optional[DiagnosisResult] = Field(default=None, description="Hybrid engine result")

    # Evaluation
    rule_based_correct_class: bool = Field(default=False)
    rule_based_correct_location: bool = Field(default=False)
    llm_correct_class: bool = Field(default=False)
    llm_correct_location: bool = Field(default=False)
    ml_correct_class: bool = Field(default=False)
    ml_correct_location: bool = Field(default=False)
    hybrid_correct_class: bool = Field(default=False)
    hybrid_correct_location: bool = Field(default=False)
