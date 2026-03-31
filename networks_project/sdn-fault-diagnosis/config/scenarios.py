"""
Synthetic config-error scenarios for testing the config-fix pipeline.

6 scenarios covering the most common OSPF configuration mistakes:
1. ospf_area_mismatch     — wrong area ID on network statement
2. missing_network        — host subnet not advertised in OSPF
3. missing_router_id      — no explicit router-id configured
4. duplicate_router_id    — router-id conflicts with another router
5. interface_typo         — interface name misspelled (et2 vs eth2)
6. missing_auth           — OSPF authentication missing on an interface
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class ConfigScenario:
    name: str
    broken_config: Path
    intent: Path
    fixed_config: Path
    description: str = ""
    expected_error_codes: List[str] = None

    def __post_init__(self):
        if self.expected_error_codes is None:
            self.expected_error_codes = []


def _fixture_path(*parts: str) -> Path:
    return Path(__file__).parent.parent / "tests" / "fixtures" / "config_errors" / Path(*parts)


SCENARIOS: Dict[str, ConfigScenario] = {
    "ospf_area_mismatch": ConfigScenario(
        name="ospf_area_mismatch",
        broken_config=_fixture_path("ospf_area_mismatch", "broken.conf"),
        intent=_fixture_path("ospf_area_mismatch", "intent.json"),
        fixed_config=_fixture_path("ospf_area_mismatch", "fixed.conf"),
        description="Wrong area ID on network statement (area 1 instead of area 0)",
        expected_error_codes=["AREA_MISMATCH", "MISSING_IF_AREA"],
    ),
    "missing_network": ConfigScenario(
        name="missing_network",
        broken_config=_fixture_path("missing_network", "broken.conf"),
        intent=_fixture_path("missing_network", "intent.json"),
        fixed_config=_fixture_path("missing_network", "fixed.conf"),
        description="Host subnet 192.168.2.0/24 not advertised in OSPF",
        expected_error_codes=["MISSING_NETWORK"],
    ),
    "missing_router_id": ConfigScenario(
        name="missing_router_id",
        broken_config=_fixture_path("missing_router_id", "broken.conf"),
        intent=_fixture_path("missing_router_id", "intent.json"),
        fixed_config=_fixture_path("missing_router_id", "fixed.conf"),
        description="No explicit router-id configured (will auto-select, may be unstable)",
        expected_error_codes=["MISSING_ROUTER_ID"],
    ),
    "duplicate_router_id": ConfigScenario(
        name="duplicate_router_id",
        broken_config=_fixture_path("duplicate_router_id", "broken.conf"),
        intent=_fixture_path("duplicate_router_id", "intent.json"),
        fixed_config=_fixture_path("duplicate_router_id", "fixed.conf"),
        description="Router-id 10.0.0.1 conflicts with spine1 (should be 10.0.1.4)",
        expected_error_codes=["ROUTER_ID_MISMATCH"],
    ),
    "interface_typo": ConfigScenario(
        name="interface_typo",
        broken_config=_fixture_path("interface_typo", "broken.conf"),
        intent=_fixture_path("interface_typo", "intent.json"),
        fixed_config=_fixture_path("interface_typo", "fixed.conf"),
        description="Interface 'et2' misspelled (should be 'eth2')",
        expected_error_codes=["MISSING_INTERFACE"],
    ),
    "missing_auth": ConfigScenario(
        name="missing_auth",
        broken_config=_fixture_path("route_map_missing", "broken.conf"),
        intent=_fixture_path("route_map_missing", "intent.json"),
        fixed_config=_fixture_path("route_map_missing", "fixed.conf"),
        description="OSPF authentication missing on eth1 (required by intent)",
        expected_error_codes=["MISSING_AUTH"],
    ),
}


def get_scenario(name: str) -> Optional[ConfigScenario]:
    return SCENARIOS.get(name)


def get_all_scenarios() -> List[ConfigScenario]:
    return list(SCENARIOS.values())
