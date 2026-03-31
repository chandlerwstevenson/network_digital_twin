"""
Feature extraction from NetworkSnapshot objects for ML-based diagnosis.

Converts telemetry snapshots into fixed-length numeric feature vectors
suitable for scikit-learn classifiers. Three tiers of features:

1. Per-router features (14 × 8 routers = 112)
2. Cross-router / topological features (28)
3. Aggregate network-wide features (6)

Total per snapshot: 146.  With delta (current − previous): 292.
"""

import numpy as np
from typing import Optional

import sys
sys.path.insert(0, str(__file__).rsplit('/', 2)[0])

from telemetry.schemas import NetworkSnapshot, RouterTelemetry


# Canonical router ordering for consistent feature vectors
ROUTER_ORDER = [
    "leaf1", "leaf2", "leaf3", "leaf4",
    "spine1", "spine2", "spine3", "spine4",
]

SPINE_ROUTERS = {"spine1", "spine2", "spine3", "spine4"}
LEAF_ROUTERS = {"leaf1", "leaf2", "leaf3", "leaf4"}

EXPECTED_HOST_SUBNETS = {
    "192.168.1.0/24", "192.168.2.0/24",
    "192.168.3.0/24", "192.168.4.0/24",
}

# Spine-leaf adjacency pairs for symmetry checking
SPINE_LEAF_PAIRS = [
    (s, l)
    for s in ["spine1", "spine2", "spine3", "spine4"]
    for l in ["leaf1", "leaf2", "leaf3", "leaf4"]
]

# Feature counts
_PER_ROUTER_FEATURES = 14
_CROSS_ROUTER_FEATURES = 27
_AGGREGATE_FEATURES = 6
SINGLE_SNAPSHOT_FEATURES = (
    _PER_ROUTER_FEATURES * len(ROUTER_ORDER)
    + _CROSS_ROUTER_FEATURES
    + _AGGREGATE_FEATURES
)
TOTAL_FEATURES = SINGLE_SNAPSHOT_FEATURES * 2


class FeatureExtractor:
    """
    Extracts fixed-length feature vectors from NetworkSnapshot objects.

    Three tiers of features capture local, relational, and global signals:

    Per-router (14 each):
        Neighbor counts, interface health, counter rates, LSDB state, route counts.

    Cross-router (28):
        Adjacency symmetry, LSDB consistency, tier-level aggregations,
        error-rate dispersion, route-table agreement, neighbor-state entropy.

    Aggregate (6):
        Network-wide totals and maximums.

    When a previous snapshot is provided, delta features (current − previous)
    are appended, doubling the vector to 292 features.
    """

    def __init__(self, router_order: list[str] = None):
        self.router_order = router_order or ROUTER_ORDER

    def extract(
        self,
        snapshot: NetworkSnapshot,
        previous_snapshot: Optional[NetworkSnapshot] = None,
    ) -> np.ndarray:
        current = self._extract_single(snapshot)

        if previous_snapshot is not None:
            previous = self._extract_single(previous_snapshot)
            delta = current - previous
        else:
            delta = np.zeros_like(current)

        return np.concatenate([current, delta])

    # ------------------------------------------------------------------
    # Single-snapshot extraction
    # ------------------------------------------------------------------

    def _extract_single(self, snapshot: NetworkSnapshot) -> np.ndarray:
        router_feats = []
        for name in self.router_order:
            if name in snapshot.routers:
                router_feats.append(
                    self._extract_router_features(snapshot.routers[name])
                )
            else:
                router_feats.append(self._missing_router_features())

        cross = self._extract_cross_router_features(snapshot)
        agg = self._extract_aggregate_features(snapshot)
        return np.concatenate(router_feats + [cross, agg])

    # ------------------------------------------------------------------
    # Tier 1: Per-router features (14 per router)
    # ------------------------------------------------------------------

    def _extract_router_features(self, t: RouterTelemetry) -> np.ndarray:
        n_total = len(t.neighbors)
        n_full = len(t.full_adjacencies)
        n_non_full = len(t.non_full_adjacencies)
        frac_full = n_full / n_total if n_total > 0 else 1.0

        ifaces = t.interfaces
        n_down = sum(1 for i in ifaces.values() if i.link_status.lower() == "down")

        err = [i.counters.error_rate for i in ifaces.values()]
        drp = [i.counters.drop_rate for i in ifaces.values()]
        max_err = max(err) if err else 0.0
        max_drp = max(drp) if drp else 0.0
        mean_err = float(np.mean(err)) if err else 0.0
        mean_drp = float(np.mean(drp)) if drp else 0.0

        n_lsas = len(t.lsdb.router_lsas)
        total_links = sum(l.link_count for l in t.lsdb.router_lsas)

        all_routes = [r for rs in t.routing_table.routes.values() for r in rs]
        n_routes = len(all_routes)
        n_static = sum(1 for r in all_routes if r.protocol == "static")
        n_ospf = sum(1 for r in all_routes if r.protocol == "ospf")

        return np.array([
            n_total, n_full, n_non_full, frac_full,
            n_down,
            max_err, max_drp, mean_err, mean_drp,
            n_lsas, total_links,
            n_routes, n_static, n_ospf,
        ], dtype=np.float64)

    def _missing_router_features(self) -> np.ndarray:
        return np.array([
            -1, -1, -1, 0.0,
            -1,
            0.0, 0.0, 0.0, 0.0,
            -1, -1,
            -1, 0, -1,
        ], dtype=np.float64)

    # ------------------------------------------------------------------
    # Tier 2: Cross-router / topological features (28)
    # ------------------------------------------------------------------

    def _extract_cross_router_features(self, snap: NetworkSnapshot) -> np.ndarray:
        routers = snap.routers

        # --- Adjacency symmetry (4 features) ---
        # How many spine-leaf pairs disagree on neighbor state?
        asymmetric_pairs = 0
        both_non_full = 0
        one_side_missing = 0
        for spine, leaf in SPINE_LEAF_PAIRS:
            s_tel = routers.get(spine)
            l_tel = routers.get(leaf)
            if not s_tel or not l_tel:
                one_side_missing += 1
                continue
            s_sees_l = any(
                n.neighbor_id == (routers[leaf].router_id if leaf in routers else "")
                for n in s_tel.neighbors
            )
            l_sees_s = any(
                n.neighbor_id == (routers[spine].router_id if spine in routers else "")
                for n in l_tel.neighbors
            )
            s_full = any(
                n.neighbor_id == routers.get(leaf, RouterTelemetry(router_name="x")).router_id
                and n.is_full
                for n in (s_tel.neighbors if s_tel else [])
            )
            l_full = any(
                n.neighbor_id == routers.get(spine, RouterTelemetry(router_name="x")).router_id
                and n.is_full
                for n in (l_tel.neighbors if l_tel else [])
            )
            if s_full != l_full:
                asymmetric_pairs += 1
            if not s_full and not l_full and s_sees_l and l_sees_s:
                both_non_full += 1
        total_pairs = len(SPINE_LEAF_PAIRS)
        asymmetry_ratio = asymmetric_pairs / total_pairs

        # --- LSDB consistency (4 features) ---
        # Do all routers agree on the set of Router-LSA IDs?
        lsa_sets = {}
        for name, t in routers.items():
            lsa_sets[name] = frozenset(l.lsa_id for l in t.lsdb.router_lsas)
        all_lsa_ids = frozenset().union(*lsa_sets.values()) if lsa_sets else frozenset()
        lsdb_disagreement = 0
        min_lsa_count = len(all_lsa_ids)
        max_lsa_count = 0
        for name, ids in lsa_sets.items():
            if ids != all_lsa_ids:
                lsdb_disagreement += 1
            min_lsa_count = min(min_lsa_count, len(ids))
            max_lsa_count = max(max_lsa_count, len(ids))
        lsdb_spread = max_lsa_count - min_lsa_count

        # --- Link-count consistency (2 features) ---
        # Variance of link counts across all Router-LSAs that share the same ID
        link_counts_per_lsa: dict[str, list[int]] = {}
        for t in routers.values():
            for lsa in t.lsdb.router_lsas:
                link_counts_per_lsa.setdefault(lsa.lsa_id, []).append(lsa.link_count)
        link_count_vars = [
            float(np.var(counts)) for counts in link_counts_per_lsa.values()
            if len(counts) > 1
        ]
        mean_link_count_var = float(np.mean(link_count_vars)) if link_count_vars else 0.0
        max_link_count_var = max(link_count_vars) if link_count_vars else 0.0

        # --- Tier-level aggregations (8 features) ---
        spine_full = sum(
            len(routers[s].full_adjacencies) for s in SPINE_ROUTERS if s in routers
        )
        spine_non_full = sum(
            len(routers[s].non_full_adjacencies) for s in SPINE_ROUTERS if s in routers
        )
        leaf_full = sum(
            len(routers[l].full_adjacencies) for l in LEAF_ROUTERS if l in routers
        )
        leaf_non_full = sum(
            len(routers[l].non_full_adjacencies) for l in LEAF_ROUTERS if l in routers
        )
        spine_down_ifaces = sum(
            1
            for s in SPINE_ROUTERS if s in routers
            for iface in routers[s].interfaces.values()
            if iface.link_status.lower() == "down"
        )
        leaf_down_ifaces = sum(
            1
            for l in LEAF_ROUTERS if l in routers
            for iface in routers[l].interfaces.values()
            if iface.link_status.lower() == "down"
        )
        spine_max_err = max(
            (iface.counters.error_rate
             for s in SPINE_ROUTERS if s in routers
             for iface in routers[s].interfaces.values()),
            default=0.0,
        )
        leaf_max_err = max(
            (iface.counters.error_rate
             for l in LEAF_ROUTERS if l in routers
             for iface in routers[l].interfaces.values()),
            default=0.0,
        )

        # --- Error-rate dispersion (3 features) ---
        all_err_rates = [
            iface.counters.error_rate
            for t in routers.values()
            for iface in t.interfaces.values()
        ]
        all_drp_rates = [
            iface.counters.drop_rate
            for t in routers.values()
            for iface in t.interfaces.values()
        ]
        err_std = float(np.std(all_err_rates)) if all_err_rates else 0.0
        drp_std = float(np.std(all_drp_rates)) if all_drp_rates else 0.0
        # How many interfaces have error rate > 1%?
        n_ifaces_with_errors = sum(1 for e in all_err_rates if e > 1.0)

        # --- Route-table agreement (4 features) ---
        # Do all spines have all 4 host subnets?
        spine_missing_subnets = 0
        for s in SPINE_ROUTERS:
            if s in routers:
                present = set(routers[s].routing_table.routes.keys())
                spine_missing_subnets += len(EXPECTED_HOST_SUBNETS - present)
        # Total static routes across all routers
        total_static_routes = sum(
            1
            for t in routers.values()
            for rs in t.routing_table.routes.values()
            for r in rs
            if r.protocol == "static"
        )
        # Route count variance across routers
        route_counts = [
            len(list(rs for rss in t.routing_table.routes.values() for rs in rss))
            for t in routers.values()
        ]
        route_count_std = float(np.std(route_counts)) if route_counts else 0.0

        # --- Neighbor-state entropy (3 features) ---
        # Distribution of neighbor states across the network
        state_counts: dict[str, int] = {}
        total_nbrs = 0
        for t in routers.values():
            for n in t.neighbors:
                s = n.state.lower().split("/")[0]  # handle "Full/-"
                state_counts[s] = state_counts.get(s, 0) + 1
                total_nbrs += 1
        # Shannon entropy of neighbor state distribution
        if total_nbrs > 0:
            probs = np.array(list(state_counts.values()), dtype=np.float64) / total_nbrs
            nbr_entropy = float(-np.sum(probs * np.log2(probs + 1e-12)))
        else:
            nbr_entropy = 0.0
        n_distinct_states = len(state_counts)
        frac_full_global = state_counts.get("full", 0) / total_nbrs if total_nbrs > 0 else 1.0

        return np.array([
            # Adjacency symmetry (4)
            asymmetric_pairs, both_non_full, one_side_missing, asymmetry_ratio,
            # LSDB consistency (4)
            lsdb_disagreement, lsdb_spread, mean_link_count_var, max_link_count_var,
            # Tier-level (8)
            spine_full, spine_non_full, leaf_full, leaf_non_full,
            spine_down_ifaces, leaf_down_ifaces, spine_max_err, leaf_max_err,
            # Error dispersion (3)
            err_std, drp_std, n_ifaces_with_errors,
            # Route agreement (4)
            spine_missing_subnets, total_static_routes, route_count_std,
            len(route_counts),  # num routers with routing table
            # Neighbor entropy (3)
            nbr_entropy, n_distinct_states, frac_full_global,
            # Padding to 28
            total_nbrs,
        ], dtype=np.float64)

    # ------------------------------------------------------------------
    # Tier 3: Aggregate features (6)
    # ------------------------------------------------------------------

    def _extract_aggregate_features(self, snap: NetworkSnapshot) -> np.ndarray:
        total_full = snap.total_full_adjacencies
        total_neighbors = snap.total_neighbors
        total_routers = len(snap.routers)

        total_down = 0
        max_error = 0.0
        max_drop = 0.0
        for t in snap.routers.values():
            for iface in t.interfaces.values():
                if iface.link_status.lower() == "down":
                    total_down += 1
                max_error = max(max_error, iface.counters.error_rate)
                max_drop = max(max_drop, iface.counters.drop_rate)

        return np.array([
            total_full, total_neighbors, total_routers,
            total_down, max_error, max_drop,
        ], dtype=np.float64)

    # ------------------------------------------------------------------
    # Feature name metadata
    # ------------------------------------------------------------------

    def feature_names(self) -> list[str]:
        per_router = [
            "num_neighbors", "num_full", "num_non_full", "fraction_full",
            "num_interfaces_down",
            "max_error_rate", "max_drop_rate", "mean_error_rate", "mean_drop_rate",
            "num_router_lsas", "total_lsa_link_count",
            "num_routes", "num_static_routes", "num_ospf_routes",
        ]
        cross = [
            "asymmetric_pairs", "both_non_full_pairs", "one_side_missing_pairs",
            "asymmetry_ratio",
            "lsdb_disagreement", "lsdb_spread", "mean_link_count_var",
            "max_link_count_var",
            "spine_full", "spine_non_full", "leaf_full", "leaf_non_full",
            "spine_down_ifaces", "leaf_down_ifaces", "spine_max_err", "leaf_max_err",
            "err_rate_std", "drp_rate_std", "n_ifaces_with_errors",
            "spine_missing_subnets", "total_static_routes", "route_count_std",
            "n_routers_with_routes",
            "neighbor_state_entropy", "n_distinct_neighbor_states",
            "fraction_full_global", "total_neighbor_count",
        ]
        aggregate = [
            "total_full_adjacencies", "total_neighbors", "total_routers",
            "total_interfaces_down", "global_max_error_rate", "global_max_drop_rate",
        ]

        names = []
        for router in self.router_order:
            for feat in per_router:
                names.append(f"{router}_{feat}")
        names.extend(cross)
        names.extend(aggregate)

        delta_names = [f"delta_{n}" for n in names]
        return names + delta_names
