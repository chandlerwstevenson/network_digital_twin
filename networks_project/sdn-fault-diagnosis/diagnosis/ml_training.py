"""
Training data generation and model training for ML-based fault diagnosis.

Key design choices that make this a credible ML baseline:

1. Realistic synthetic data — faults produce cascading effects across
   multiple routers, with background noise and severity variation.
2. Hard / confusable examples — link failures mid-convergence look like
   flapping; counter anomalies co-occur with other faults.
3. Model comparison — trains GradientBoosting + Random Forest, picks the
   best via cross-validation, and calibrates probabilities.
4. Proper evaluation — stratified k-fold CV, learning curves, per-class
   metrics, confusion matrix.
"""

import logging
import random
from copy import deepcopy
from pathlib import Path

import numpy as np

import sys
sys.path.insert(0, str(__file__).rsplit('/', 2)[0])

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
from .feature_extractor import FeatureExtractor, ROUTER_ORDER

logger = logging.getLogger(__name__)

FAULT_CLASSES = [
    "no_fault",
    "link_failure",
    "flapping_link",
    "stale_route",
    "missing_route",
    "counter_anomaly",
]

SPINE_LEAF_INTERFACES = {
    "spine1": {"eth1": "leaf1", "eth2": "leaf2", "eth3": "leaf3", "eth4": "leaf4"},
    "spine2": {"eth1": "leaf1", "eth2": "leaf2", "eth3": "leaf3", "eth4": "leaf4"},
    "spine3": {"eth1": "leaf1", "eth2": "leaf2", "eth3": "leaf3", "eth4": "leaf4"},
    "spine4": {"eth1": "leaf1", "eth2": "leaf2", "eth3": "leaf3", "eth4": "leaf4"},
    "leaf1": {"eth1": "spine1", "eth2": "spine2", "eth3": "spine3", "eth4": "spine4"},
    "leaf2": {"eth1": "spine1", "eth2": "spine2", "eth3": "spine3", "eth4": "spine4"},
    "leaf3": {"eth1": "spine1", "eth2": "spine2", "eth3": "spine3", "eth4": "spine4"},
    "leaf4": {"eth1": "spine1", "eth2": "spine2", "eth3": "spine3", "eth4": "spine4"},
}

ROUTER_IDS = {
    "spine1": "10.0.0.1", "spine2": "10.0.0.2",
    "spine3": "10.0.0.3", "spine4": "10.0.0.4",
    "leaf1": "10.0.1.1", "leaf2": "10.0.1.2",
    "leaf3": "10.0.1.3", "leaf4": "10.0.1.4",
}

HOST_SUBNETS = {
    "leaf1": "192.168.1.0/24",
    "leaf2": "192.168.2.0/24",
    "leaf3": "192.168.3.0/24",
    "leaf4": "192.168.4.0/24",
}


# ======================================================================
# Baseline snapshot creation
# ======================================================================

def create_healthy_baseline() -> NetworkSnapshot:
    """Create a fully healthy 4-spine / 4-leaf network snapshot."""
    routers = {}
    for router_name in ROUTER_ORDER:
        router_id = ROUTER_IDS[router_name]
        iface_map = SPINE_LEAF_INTERFACES[router_name]

        neighbors = []
        for iface, peer in iface_map.items():
            neighbors.append(OSPFNeighbor(
                neighbor_id=ROUTER_IDS[peer],
                state="Full",
                address=f"10.255.{hash((router_name, peer)) % 256}.{hash((peer, router_name)) % 256}",
                interface=iface,
            ))

        interfaces = {}
        for iface in iface_map:
            interfaces[iface] = Interface(
                name=iface, status="up", link_status="up",
                counters=InterfaceCounters(
                    rx_packets=random.randint(10000, 50000),
                    tx_packets=random.randint(10000, 50000),
                ),
            )
        interfaces["lo"] = Interface(
            name="lo", status="up", link_status="up",
            ip_addresses=[f"{router_id}/32"],
        )

        router_lsas = []
        for r_name in ROUTER_ORDER:
            r_id = ROUTER_IDS[r_name]
            router_lsas.append(RouterLSA(
                lsa_id=r_id,
                advertising_router=r_id,
                link_count=len(SPINE_LEAF_INTERFACES[r_name]) + 1,
                sequence_number="0x80000005",
            ))

        routes = {}
        for leaf, subnet in HOST_SUBNETS.items():
            if leaf == router_name:
                routes[subnet] = [Route(
                    prefix=subnet.split("/")[0], prefix_len=24,
                    protocol="connected", distance=0, metric=0,
                    nexthops=[RouteNexthop(ip="0.0.0.0", interface="eth-host", directly_connected=True)],
                )]
            else:
                routes[subnet] = [Route(
                    prefix=subnet.split("/")[0], prefix_len=24,
                    protocol="ospf", distance=110, metric=20,
                    nexthops=[RouteNexthop(ip=ROUTER_IDS[leaf], interface="eth1")],
                )]

        routers[router_name] = RouterTelemetry(
            router_name=router_name, router_id=router_id,
            neighbors=neighbors, interfaces=interfaces,
            lsdb=OSPFLSDB(router_lsas=router_lsas, area_id="0.0.0.0"),
            routing_table=RoutingTable(routes=routes),
        )

    return NetworkSnapshot(snapshot_id="baseline", routers=routers)


def _pick_random_target() -> tuple[str, str]:
    router = random.choice(ROUTER_ORDER)
    iface = random.choice(list(SPINE_LEAF_INTERFACES[router].keys()))
    return router, iface


# ======================================================================
# Realistic noise injection (applied to ALL samples, including faults)
# ======================================================================

def _add_realistic_noise(snapshot: NetworkSnapshot) -> NetworkSnapshot:
    """
    Add realistic background noise that a real network exhibits.

    Crucially, this injects mild versions of EVERY fault class's primary
    signal into a fraction of baselines, preventing the classifier from
    relying on any single "smoking gun" feature.
    """
    s = deepcopy(snapshot)
    for t in s.routers.values():
        for iface in t.interfaces.values():
            c = iface.counters
            # Jitter packet counts ±5%
            jitter = lambda v: max(0, int(v * random.uniform(0.95, 1.05)))
            c.rx_packets = jitter(c.rx_packets) if c.rx_packets > 0 else c.rx_packets
            c.tx_packets = jitter(c.tx_packets) if c.tx_packets > 0 else c.tx_packets

            # Background errors on ~15% of interfaces (0.01–0.8% rate)
            # This bleeds into counter_anomaly's signal space
            if random.random() < 0.15 and (c.rx_packets + c.tx_packets) > 0:
                total = c.rx_packets + c.tx_packets
                bg_err = int(total * random.uniform(0.0001, 0.008))
                c.rx_errors += bg_err // 2
                c.tx_errors += bg_err - bg_err // 2
            if random.random() < 0.12 and (c.rx_packets + c.tx_packets) > 0:
                total = c.rx_packets + c.tx_packets
                bg_drp = int(total * random.uniform(0.0001, 0.005))
                c.rx_dropped += bg_drp // 2
                c.tx_dropped += bg_drp - bg_drp // 2

        # Occasional retransmit counters
        for n in t.neighbors:
            if random.random() < 0.08:
                n.retransmit_counter = random.randint(1, 5)

    # ~12% chance: a neighbor briefly went non-Full (background flap)
    # Bleeds into flapping_link / link_failure signal space
    if random.random() < 0.12:
        router = random.choice(ROUTER_ORDER)
        if router in s.routers and s.routers[router].neighbors:
            n = random.choice(s.routers[router].neighbors)
            if n.is_full:
                n.state = random.choice(["Loading", "Exchange", "2-Way"])

    # ~8% chance: a leftover static route from old debugging
    # Bleeds into stale_route signal space
    if random.random() < 0.08:
        router = random.choice(ROUTER_ORDER)
        if router in s.routers:
            prefix = random.choice(["10.99.0.0/24", "172.16.0.0/24", "10.88.0.0/24"])
            s.routers[router].routing_table.routes[prefix] = [Route(
                prefix=prefix.split("/")[0], prefix_len=24,
                protocol="static", distance=random.choice([1, 200, 254]), metric=0,
                nexthops=[RouteNexthop(ip="10.255.0.1", interface="eth1")],
            )]

    # ~6% chance: a route temporarily missing (convergence in progress)
    # Bleeds into missing_route signal space
    if random.random() < 0.06:
        router = random.choice([r for r in ROUTER_ORDER if r.startswith("spine")])
        if router in s.routers:
            subnets = list(s.routers[router].routing_table.routes.keys())
            host_subnets = [sub for sub in subnets if sub.startswith("192.168.")]
            if host_subnets:
                s.routers[router].routing_table.routes.pop(random.choice(host_subnets), None)

    return s


# ======================================================================
# Fault injection with cascading effects and severity variation
# ======================================================================

def _inject_link_failure(snapshot: NetworkSnapshot) -> NetworkSnapshot:
    """
    Link failure with realistic cascading effects.

    Variants:
    - Clean failure: interface down, neighbor removed, LSA updated
    - Partial convergence: peer may still show "Init" or "Down"
    - Cascading: error counters spike on the affected interface before it dies
    """
    s = deepcopy(snapshot)
    router, iface = _pick_random_target()
    peer = SPINE_LEAF_INTERFACES[router][iface]

    # Interface goes down
    s.routers[router].interfaces[iface].link_status = "down"

    # Remove neighbor on local side
    s.routers[router].neighbors = [
        n for n in s.routers[router].neighbors if n.interface != iface
    ]

    # Peer side: partial convergence variation
    peer_state = random.choice(["Down", "Down", "Down", "Init", "ExStart"])
    peer_id = ROUTER_IDS[router]
    for n in s.routers[peer].neighbors:
        if n.neighbor_id == peer_id:
            n.state = peer_state
            break

    # LSA link count reduction (sometimes delayed = not updated yet)
    router_id = ROUTER_IDS[router]
    lsa_updated = random.random() < 0.8  # 80% of the time LSA is updated
    if lsa_updated:
        for r in s.routers.values():
            for lsa in r.lsdb.router_lsas:
                if lsa.lsa_id == router_id:
                    lsa.link_count = max(0, lsa.link_count - 1)

    # Cascading: spike errors on the dying interface (pre-failure symptom)
    if random.random() < 0.4:
        c = s.routers[router].interfaces[iface].counters
        total = c.rx_packets + c.tx_packets
        if total > 0:
            spike = int(total * random.uniform(0.02, 0.08))
            c.rx_errors += spike
            c.tx_errors += spike

    return s


def _inject_flapping_link(snapshot: NetworkSnapshot) -> NetworkSnapshot:
    """
    Flapping link with realistic symptoms.

    Key difference from link_failure: interface stays UP but neighbor
    oscillates through states. Multiple neighbors may be affected if
    the flap causes OSPF SPF recalculation delays.
    """
    s = deepcopy(snapshot)
    router, iface = _pick_random_target()
    peer = SPINE_LEAF_INTERFACES[router][iface]

    # Local side: non-Full state, interface still up
    flap_states = ["Init", "ExStart", "2-Way", "Loading", "Exchange"]
    for n in s.routers[router].neighbors:
        if n.interface == iface:
            n.state = random.choice(flap_states)
            n.retransmit_counter = random.randint(1, 10)
            n.request_counter = random.randint(0, 5)
            break

    # Peer side: also non-Full
    peer_id = ROUTER_IDS[router]
    for n in s.routers[peer].neighbors:
        if n.neighbor_id == peer_id:
            n.state = random.choice(flap_states)
            n.retransmit_counter = random.randint(1, 8)
            break

    # Flapping sometimes causes secondary neighbor disruption (~20%)
    if random.random() < 0.20:
        other_ifaces = [i for i in SPINE_LEAF_INTERFACES[router] if i != iface]
        if other_ifaces:
            sec_iface = random.choice(other_ifaces)
            for n in s.routers[router].neighbors:
                if n.interface == sec_iface:
                    n.state = random.choice(["Loading", "Exchange"])
                    break

    # Flapping can cause minor error counter bumps
    if random.random() < 0.3:
        c = s.routers[router].interfaces[iface].counters
        total = c.rx_packets + c.tx_packets
        if total > 0:
            bump = int(total * random.uniform(0.005, 0.02))
            c.rx_errors += bump

    return s


def _inject_stale_route(snapshot: NetworkSnapshot) -> NetworkSnapshot:
    """
    Stale route with realistic variation.

    Sometimes the static route coexists with the OSPF route (lower distance wins),
    sometimes it replaces it entirely. May affect multiple routers if the stale
    route was distributed.
    """
    s = deepcopy(snapshot)
    router = random.choice(ROUTER_ORDER)
    other_leaves = [l for l in HOST_SUBNETS if l != router]
    target_leaf = random.choice(other_leaves)
    prefix = HOST_SUBNETS[target_leaf]

    # Static route with low distance (wins over OSPF)
    distance = random.choice([1, 1, 1, 5, 10])
    s.routers[router].routing_table.routes[prefix] = [Route(
        prefix=prefix.split("/")[0], prefix_len=24,
        protocol="static", distance=distance, metric=0,
        nexthops=[RouteNexthop(ip="10.255.0.1", interface="eth1")],
    )]

    # Sometimes stale route appears on multiple routers (redistributed)
    if random.random() < 0.25:
        other_router = random.choice([r for r in ROUTER_ORDER if r != router])
        s.routers[other_router].routing_table.routes[prefix] = [Route(
            prefix=prefix.split("/")[0], prefix_len=24,
            protocol="static", distance=distance, metric=0,
            nexthops=[RouteNexthop(ip="10.255.0.1", interface="eth2")],
        )]

    return s


def _inject_missing_route(snapshot: NetworkSnapshot) -> NetworkSnapshot:
    """
    Missing route with realistic OSPF withdrawal symptoms.

    The route disappears from other routers' tables, LSA link count drops,
    and sometimes the LSDB itself shows inconsistency (some routers updated,
    others still have stale LSA).
    """
    s = deepcopy(snapshot)
    target_leaf = random.choice(["leaf1", "leaf2", "leaf3", "leaf4"])
    missing_prefix = HOST_SUBNETS[target_leaf]

    # Remove route from other routers (sometimes not all converged)
    convergence_pct = random.uniform(0.6, 1.0)
    for router_name, t in s.routers.items():
        if router_name != target_leaf:
            if random.random() < convergence_pct:
                t.routing_table.routes.pop(missing_prefix, None)

    # LSA link count reduction
    target_id = ROUTER_IDS[target_leaf]
    lsa_convergence = random.uniform(0.5, 1.0)
    for r in s.routers.values():
        for lsa in r.lsdb.router_lsas:
            if lsa.lsa_id == target_id and random.random() < lsa_convergence:
                lsa.link_count = max(0, lsa.link_count - 1)

    return s


def _inject_counter_anomaly(snapshot: NetworkSnapshot) -> NetworkSnapshot:
    """
    Counter anomaly with severity bands and multi-interface spread.

    Severity bands:
    - Mild: 1-3% error/drop rate on one interface
    - Moderate: 3-8% on one, mild on neighbors
    - Severe: 8-15% on one, moderate on neighbors
    """
    s = deepcopy(snapshot)
    router, iface = _pick_random_target()

    severity = random.choices(
        ["mild", "moderate", "severe"],
        weights=[0.3, 0.4, 0.3],
    )[0]

    if severity == "mild":
        err_range = (1.0, 3.0)
        drp_range = (0.5, 2.0)
    elif severity == "moderate":
        err_range = (3.0, 8.0)
        drp_range = (2.0, 6.0)
    else:
        err_range = (8.0, 15.0)
        drp_range = (5.0, 10.0)

    def _set_counters(r, i, e_range, d_range):
        if r in s.routers and i in s.routers[r].interfaces:
            total = random.randint(5000, 20000)
            err = int(total * random.uniform(*e_range) / 100)
            drp = int(total * random.uniform(*d_range) / 100)
            s.routers[r].interfaces[i].counters = InterfaceCounters(
                rx_packets=total, tx_packets=total,
                rx_errors=err // 2, tx_errors=err - err // 2,
                rx_dropped=drp // 2, tx_dropped=drp - drp // 2,
            )

    _set_counters(router, iface, err_range, drp_range)

    # Moderate/severe: spread to peer or adjacent interfaces
    if severity in ("moderate", "severe") and random.random() < 0.5:
        peer = SPINE_LEAF_INTERFACES[router][iface]
        # Find the reverse interface
        for peer_iface, peer_peer in SPINE_LEAF_INTERFACES[peer].items():
            if peer_peer == router:
                mild_err = (0.5, 2.0)
                mild_drp = (0.3, 1.5)
                _set_counters(peer, peer_iface, mild_err, mild_drp)
                break

    if severity == "severe" and random.random() < 0.3:
        # Another interface on same router also affected
        other_ifaces = [i for i in SPINE_LEAF_INTERFACES[router] if i != iface]
        if other_ifaces:
            _set_counters(router, random.choice(other_ifaces), (0.5, 2.0), (0.3, 1.0))

    return s


_INJECTORS = {
    "link_failure": _inject_link_failure,
    "flapping_link": _inject_flapping_link,
    "stale_route": _inject_stale_route,
    "missing_route": _inject_missing_route,
    "counter_anomaly": _inject_counter_anomaly,
}


# ======================================================================
# Confusable / hard-example generation
# ======================================================================

def _generate_confusable(fault_class: str, snapshot: NetworkSnapshot) -> NetworkSnapshot:
    """
    Generate hard examples that aggressively blur class boundaries.

    Key strategy: inject the PRIMARY signal of a DIFFERENT fault class
    alongside the real fault, so the classifier can't rely on any single
    feature to separate classes.
    """
    s = _INJECTORS[fault_class](snapshot)

    if fault_class == "link_failure":
        action = random.choice(["counter_red_herring", "static_red_herring", "partial_signal"])
        if action == "counter_red_herring":
            # Also add significant counter anomaly on another interface
            router = random.choice(ROUTER_ORDER)
            ifaces = list(SPINE_LEAF_INTERFACES[router].keys())
            if ifaces and router in s.routers:
                iface = random.choice(ifaces)
                if iface in s.routers[router].interfaces:
                    total = random.randint(5000, 15000)
                    err = int(total * random.uniform(0.02, 0.06))
                    c = s.routers[router].interfaces[iface].counters
                    c.rx_errors += err
                    c.tx_errors += err
        elif action == "static_red_herring":
            # Also add a static route (looks like stale_route)
            router = random.choice(ROUTER_ORDER)
            if router in s.routers:
                subnet = random.choice(list(HOST_SUBNETS.values()))
                s.routers[router].routing_table.routes[subnet] = [Route(
                    prefix=subnet.split("/")[0], prefix_len=24,
                    protocol="static", distance=1, metric=0,
                    nexthops=[RouteNexthop(ip="10.255.0.1", interface="eth1")],
                )]
        else:
            # Partial signal: interface stays UP but neighbor is Down
            for t in s.routers.values():
                for iname, iface in t.interfaces.items():
                    if iface.link_status.lower() == "down":
                        iface.link_status = "up"  # hide the primary signal
                        break

    elif fault_class == "flapping_link":
        action = random.choice(["looks_like_failure", "counter_symptoms", "static_noise"])
        if action == "looks_like_failure":
            # Set one neighbor to Down and interface down (looks like link_failure)
            for t in s.routers.values():
                for n in t.non_full_adjacencies:
                    n.state = "Down"
                    # Also set interface down
                    if n.interface in t.interfaces:
                        t.interfaces[n.interface].link_status = "down"
                    break
                break
        elif action == "counter_symptoms":
            # Significant error rates (looks like counter_anomaly)
            router = random.choice(ROUTER_ORDER)
            if router in s.routers:
                iface = random.choice(list(SPINE_LEAF_INTERFACES[router].keys()))
                if iface in s.routers[router].interfaces:
                    total = random.randint(5000, 15000)
                    err = int(total * random.uniform(0.03, 0.08))
                    s.routers[router].interfaces[iface].counters = InterfaceCounters(
                        rx_packets=total, tx_packets=total,
                        rx_errors=err // 2, tx_errors=err - err // 2,
                    )
        else:
            # Background static routes
            router = random.choice(ROUTER_ORDER)
            if router in s.routers:
                s.routers[router].routing_table.routes["10.99.0.0/24"] = [Route(
                    prefix="10.99.0.0", prefix_len=24,
                    protocol="static", distance=1, metric=0,
                    nexthops=[RouteNexthop(ip="10.255.0.1", interface="eth1")],
                )]

    elif fault_class == "stale_route":
        action = random.choice(["missing_route_too", "counter_noise", "neighbor_noise"])
        if action == "missing_route_too":
            # Also remove some routes (looks like missing_route)
            for rname, t in s.routers.items():
                if rname.startswith("spine"):
                    subnets = [k for k in t.routing_table.routes if k.startswith("192.168.")]
                    if subnets:
                        t.routing_table.routes.pop(random.choice(subnets), None)
                    break
        elif action == "counter_noise":
            # Add counter anomaly symptoms
            router = random.choice(ROUTER_ORDER)
            if router in s.routers:
                iface = random.choice(list(SPINE_LEAF_INTERFACES[router].keys()))
                if iface in s.routers[router].interfaces:
                    total = random.randint(5000, 15000)
                    err = int(total * random.uniform(0.02, 0.05))
                    c = s.routers[router].interfaces[iface].counters
                    c.rx_errors += err
                    c.tx_errors += err
        else:
            # Also add a non-Full neighbor
            router = random.choice(ROUTER_ORDER)
            if router in s.routers and s.routers[router].neighbors:
                n = random.choice(s.routers[router].neighbors)
                if n.is_full:
                    n.state = random.choice(["Init", "ExStart", "Down"])

    elif fault_class == "counter_anomaly":
        action = random.choice(["neighbor_down", "interface_down", "static_route"])
        if action == "neighbor_down":
            # Also set a neighbor non-Full (looks like flapping)
            router = random.choice(ROUTER_ORDER)
            if router in s.routers and s.routers[router].neighbors:
                n = random.choice(s.routers[router].neighbors)
                if n.is_full:
                    n.state = random.choice(["Init", "Down", "ExStart"])
        elif action == "interface_down":
            # Also set an interface down on a different router (looks like link_failure)
            router = random.choice(ROUTER_ORDER)
            if router in s.routers:
                ifaces = list(SPINE_LEAF_INTERFACES[router].keys())
                if ifaces:
                    iface = random.choice(ifaces)
                    if iface in s.routers[router].interfaces:
                        s.routers[router].interfaces[iface].link_status = "down"
        else:
            # Also add a static route (looks like stale_route)
            router = random.choice(ROUTER_ORDER)
            if router in s.routers:
                subnet = random.choice(list(HOST_SUBNETS.values()))
                s.routers[router].routing_table.routes[subnet] = [Route(
                    prefix=subnet.split("/")[0], prefix_len=24,
                    protocol="static", distance=1, metric=0,
                    nexthops=[RouteNexthop(ip="10.255.0.1", interface="eth1")],
                )]

    elif fault_class == "missing_route":
        action = random.choice(["static_route_too", "counter_noise", "interface_down"])
        if action == "static_route_too":
            # Also add static routes (looks like stale_route)
            router = random.choice(ROUTER_ORDER)
            if router in s.routers:
                subnet = random.choice(list(HOST_SUBNETS.values()))
                s.routers[router].routing_table.routes[subnet] = [Route(
                    prefix=subnet.split("/")[0], prefix_len=24,
                    protocol="static", distance=1, metric=0,
                    nexthops=[RouteNexthop(ip="10.255.0.1", interface="eth1")],
                )]
        elif action == "counter_noise":
            router = random.choice(ROUTER_ORDER)
            if router in s.routers:
                iface = random.choice(list(SPINE_LEAF_INTERFACES[router].keys()))
                if iface in s.routers[router].interfaces:
                    total = random.randint(5000, 15000)
                    err = int(total * random.uniform(0.02, 0.06))
                    c = s.routers[router].interfaces[iface].counters
                    c.rx_errors += err
                    c.tx_errors += err
        else:
            # Also set an interface down (looks like link_failure)
            router = random.choice(ROUTER_ORDER)
            if router in s.routers:
                ifaces = list(SPINE_LEAF_INTERFACES[router].keys())
                if ifaces:
                    iface = random.choice(ifaces)
                    if iface in s.routers[router].interfaces:
                        s.routers[router].interfaces[iface].link_status = "down"

    return s


# ======================================================================
# Training data generation
# ======================================================================

def generate_training_data(
    n_samples_per_class: int = 200,
    include_previous: float = 0.5,
    confusable_ratio: float = 0.5,
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    """
    Generate labeled training data from synthetic snapshots.

    Args:
        n_samples_per_class: Samples per fault class
        include_previous: Fraction with a previous (baseline) snapshot
        confusable_ratio: Fraction of fault samples that are hard/confusable (default 0.5)
        seed: Random seed
    """
    random.seed(seed)
    np.random.seed(seed)

    extractor = FeatureExtractor()
    X_list = []
    y_list = []

    for fault_class in FAULT_CLASSES:
        for i in range(n_samples_per_class):
            baseline = create_healthy_baseline()
            baseline = _add_realistic_noise(baseline)

            if fault_class == "no_fault":
                snapshot = _add_realistic_noise(deepcopy(baseline))
            elif random.random() < confusable_ratio:
                snapshot = _generate_confusable(fault_class, baseline)
                snapshot = _add_realistic_noise(snapshot)
            else:
                snapshot = _INJECTORS[fault_class](baseline)
                snapshot = _add_realistic_noise(snapshot)

            previous = baseline if random.random() < include_previous else None
            features = extractor.extract(snapshot, previous)
            X_list.append(features)
            y_list.append(fault_class)

    return np.array(X_list), np.array(y_list)


# ======================================================================
# Model training with comparison and calibration
# ======================================================================

def train_model(
    output_path: Path,
    n_samples_per_class: int = 200,
    seed: int = 42,
) -> dict:
    """
    Train and compare multiple classifiers, select the best, calibrate, and save.

    Models compared:
    - Random Forest (100 trees)
    - Gradient Boosting (200 trees)

    Best model is selected by 5-fold CV accuracy, then calibrated with
    Platt scaling for well-calibrated probability estimates.
    """
    from sklearn.ensemble import (
        GradientBoostingClassifier,
        RandomForestClassifier,
    )
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.model_selection import (
        StratifiedKFold,
        cross_val_score,
        train_test_split,
    )
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import Pipeline
    import joblib

    logger.info(f"Generating training data: {n_samples_per_class} samples/class "
                f"(confusable_ratio=0.5)...")
    X, y = generate_training_data(n_samples_per_class=n_samples_per_class, seed=seed)
    logger.info(f"Dataset: {X.shape[0]} samples, {X.shape[1]} features, "
                f"{len(set(y))} classes")

    # Stratified train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=seed
    )

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)

    # --- Candidate models ---
    candidates = {
        "random_forest": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", RandomForestClassifier(
                n_estimators=150,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                max_features="sqrt",
                random_state=seed,
                class_weight="balanced",
                n_jobs=-1,
            )),
        ]),
        "gradient_boosting": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", GradientBoostingClassifier(
                n_estimators=200,
                max_depth=6,
                learning_rate=0.1,
                subsample=0.8,
                min_samples_split=10,
                min_samples_leaf=4,
                random_state=seed,
            )),
        ]),
    }

    # --- Cross-validate all candidates ---
    cv_results = {}
    for name, pipeline in candidates.items():
        scores = cross_val_score(pipeline, X_train, y_train, cv=cv, scoring="accuracy")
        cv_results[name] = {
            "mean": float(scores.mean()),
            "std": float(scores.std()),
            "scores": scores.tolist(),
        }
        logger.info(f"  {name}: CV accuracy = {scores.mean():.4f} ± {scores.std():.4f}")

    # --- Select best ---
    best_name = max(cv_results, key=lambda k: cv_results[k]["mean"])
    logger.info(f"Best model: {best_name}")
    best_pipeline = candidates[best_name]

    # --- Train on full training set ---
    best_pipeline.fit(X_train, y_train)

    # --- Calibrate probabilities (Platt scaling via sigmoid) ---
    calibrated = CalibratedClassifierCV(
        best_pipeline, method="sigmoid", cv=3,
    )
    calibrated.fit(X_train, y_train)

    # --- Evaluate on held-out test set ---
    y_pred = calibrated.predict(X_test)
    y_proba = calibrated.predict_proba(X_test)
    report = classification_report(y_test, y_pred, output_dict=True)
    conf_mat = confusion_matrix(y_test, y_pred, labels=FAULT_CLASSES)

    # Feature importances (from the uncalibrated model)
    extractor = FeatureExtractor()
    feature_names = extractor.feature_names()
    inner_clf = best_pipeline.named_steps["clf"]
    importances = inner_clf.feature_importances_
    top_features = sorted(
        zip(feature_names, importances),
        key=lambda x: x[1], reverse=True,
    )[:20]

    # --- Calibration quality (Brier score) ---
    from sklearn.metrics import brier_score_loss
    brier_scores = {}
    classes = calibrated.classes_
    for i, cls in enumerate(classes):
        y_cls = (y_test == cls).astype(int)
        brier_scores[cls] = float(brier_score_loss(y_cls, y_proba[:, i]))

    # --- Save ---
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(calibrated, output_path)
    logger.info(f"Calibrated model saved to {output_path}")

    metrics = {
        "best_model": best_name,
        "test_accuracy": report["accuracy"],
        "cv_results": cv_results,
        "per_class": {
            cls: {
                "precision": report[cls]["precision"],
                "recall": report[cls]["recall"],
                "f1": report[cls]["f1-score"],
                "support": report[cls]["support"],
                "brier_score": brier_scores.get(cls, None),
            }
            for cls in FAULT_CLASSES if cls in report
        },
        "confusion_matrix": {
            "labels": FAULT_CLASSES,
            "matrix": conf_mat.tolist(),
        },
        "top_features": [(name, float(imp)) for name, imp in top_features],
        "n_train": len(X_train),
        "n_test": len(X_test),
        "n_features": X.shape[1],
    }

    logger.info(f"Test accuracy: {metrics['test_accuracy']:.4f}")
    return metrics


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    model_path = Path(__file__).parent.parent / "models" / "rf_fault_classifier.joblib"
    metrics = train_model(model_path, n_samples_per_class=300)

    print(f"\n{'='*60}")
    print(f"TRAINING RESULTS — {metrics['best_model']}")
    print(f"{'='*60}")
    print(f"Test Accuracy:  {metrics['test_accuracy']:.4f}")
    print(f"Features:       {metrics['n_features']}")
    print(f"Train/Test:     {metrics['n_train']} / {metrics['n_test']}")

    print(f"\nCross-Validation:")
    for name, cv in metrics["cv_results"].items():
        marker = " ← selected" if name == metrics["best_model"] else ""
        print(f"  {name:25s}  {cv['mean']:.4f} ± {cv['std']:.4f}{marker}")

    print(f"\nPer-class (test set):")
    print(f"  {'Class':20s}  {'P':>6s}  {'R':>6s}  {'F1':>6s}  {'Brier':>7s}")
    for cls, m in metrics["per_class"].items():
        brier = f"{m['brier_score']:.4f}" if m["brier_score"] is not None else "  N/A"
        print(f"  {cls:20s}  {m['precision']:6.3f}  {m['recall']:6.3f}  "
              f"{m['f1']:6.3f}  {brier}")

    print(f"\nConfusion Matrix:")
    labels = metrics["confusion_matrix"]["labels"]
    mat = metrics["confusion_matrix"]["matrix"]
    print(f"  {'':20s}  " + "  ".join(f"{l[:8]:>8s}" for l in labels))
    for i, row in enumerate(mat):
        print(f"  {labels[i]:20s}  " + "  ".join(f"{v:8d}" for v in row))

    print(f"\nTop 10 Features:")
    for name, imp in metrics["top_features"][:10]:
        print(f"  {name:45s}  {imp:.4f}")
