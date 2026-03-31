"""
Config validator/linter for FRR-style OSPF configs.

Uses lightweight parsing to detect common issues:
- Missing router ospf stanza or router-id
- Missing or mismatched network statements vs intent
- Interface-level auth/area mismatches
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .intent import Intent, InterfaceIntent, NetworkIntent


@dataclass
class ValidationError:
    code: str
    message: str
    context: Dict[str, str] = field(default_factory=dict)


@dataclass
class ValidationReport:
    errors: List[ValidationError] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.errors

    def add(self, code: str, message: str, **context):
        self.errors.append(ValidationError(code=code, message=message, context=context))


OSPF_ROUTER_PATTERN = re.compile(r"^router ospf\b", re.MULTILINE)
ROUTER_ID_PATTERN = re.compile(r"router-id\s+([^\s]+)")
NETWORK_PATTERN = re.compile(r"network\s+([^\s]+)\s+area\s+([^\s]+)")
INTERFACE_BLOCK_PATTERN = re.compile(r"^interface\s+([^\s]+)\s*$", re.MULTILINE)
AUTH_PATTERN = re.compile(r"ip\s+ospf\s+authentication", re.IGNORECASE)
AREA_UNDER_IF_PATTERN = re.compile(r"ip\s+ospf\s+area\s+([^\s]+)", re.IGNORECASE)


def _extract_router_block(config_text: str) -> Optional[str]:
    """Return the router ospf block (if any)."""
    lines = config_text.splitlines()
    collecting = False
    block: List[str] = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("router ospf"):
            collecting = True
            block.append(stripped)
            continue
        if collecting:
            if stripped and not stripped.startswith(("!", "router ")) and not stripped.startswith("interface "):
                block.append(stripped)
            elif stripped.startswith("router ") or stripped.startswith("interface "):
                break

    return "\n".join(block) if block else None


def _parse_interfaces(config_text: str) -> Dict[str, List[str]]:
    """
    Parse interface blocks into a mapping: name -> list of lines.
    Very lightweight; assumes "interface <name>" headers.
    """
    interfaces: Dict[str, List[str]] = {}
    current: Optional[str] = None

    for line in config_text.splitlines():
        if m := INTERFACE_BLOCK_PATTERN.match(line):
            current = m.group(1)
            interfaces[current] = []
            continue
        if current:
            if line.startswith(" "):  # indented subcommand
                interfaces[current].append(line.strip())
            elif line.strip().startswith("!"):  # comment separator
                continue
            else:
                current = None

    return interfaces


def validate_config(config_text: str, intent: Optional[Intent] = None) -> ValidationReport:
    """
    Run lint/validation checks against a config.

    Args:
        config_text: FRR-style configuration text.
        intent: Desired state (optional). If provided, intent-driven checks run.
    """
    report = ValidationReport()

    router_block = _extract_router_block(config_text)
    if not router_block:
        report.add("MISSING_OSPF_PROCESS", "router ospf stanza not found")
        return report

    # Router ID
    rid_match = ROUTER_ID_PATTERN.search(router_block)
    if intent and intent.router_id:
        if not rid_match:
            report.add("MISSING_ROUTER_ID", "router-id missing", expected=intent.router_id)
        elif rid_match.group(1) != intent.router_id:
            report.add(
                "ROUTER_ID_MISMATCH",
                f"router-id {rid_match.group(1)} != expected {intent.router_id}",
                observed=rid_match.group(1),
                expected=intent.router_id,
            )

    # Network statements
    networks_in_config = {m.group(1): m.group(2) for m in NETWORK_PATTERN.finditer(router_block)}

    if intent:
        for net in intent.networks:
            _check_network(net, networks_in_config, report)

    # Interface checks
    interfaces = _parse_interfaces(config_text)
    if intent:
        for name, iface_intent in intent.interfaces.items():
            if name not in interfaces:
                report.add("MISSING_INTERFACE", f"interface {name} missing", interface=name)
                continue
            _check_interface(interfaces[name], iface_intent, report)

    return report


def _check_network(net: NetworkIntent, networks_in_config: Dict[str, str], report: ValidationReport):
    if net.prefix not in networks_in_config:
        report.add(
            "MISSING_NETWORK",
            f"network {net.prefix} missing",
            prefix=net.prefix,
            area=net.area,
        )
        return

    observed_area = str(networks_in_config[net.prefix])
    if observed_area != net.area:
        report.add(
            "AREA_MISMATCH",
            f"network {net.prefix} area {observed_area} != expected {net.area}",
            prefix=net.prefix,
            expected_area=net.area,
            observed_area=observed_area,
        )


def _check_interface(lines: List[str], intent: InterfaceIntent, report: ValidationReport):
    auth_present = any(AUTH_PATTERN.search(line) for line in lines)
    if intent.auth_required and not auth_present:
        report.add(
            "MISSING_AUTH",
            f"interface {intent.name} missing OSPF authentication",
            interface=intent.name,
        )

    if intent.area is not None:
        observed_area = None
        for line in lines:
            if m := AREA_UNDER_IF_PATTERN.search(line):
                observed_area = m.group(1)
                break
        if observed_area is None:
            report.add(
                "MISSING_IF_AREA",
                f"interface {intent.name} missing ip ospf area {intent.area}",
                interface=intent.name,
                expected_area=intent.area,
            )
        elif str(observed_area) != str(intent.area):
            report.add(
                "IF_AREA_MISMATCH",
                f"interface {intent.name} area {observed_area} != expected {intent.area}",
                interface=intent.name,
                expected_area=str(intent.area),
                observed_area=str(observed_area),
            )
